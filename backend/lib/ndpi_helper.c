/**
 * nDPI Helper — 轻量 C 桥接层
 *
 * 解决 ctypes 无法正确处理 struct-by-value 返回值的问题。
 * 封装 nDPI 检测逻辑，对外只暴露简单的整数协议 ID。
 *
 * 编译:
 *   gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c \
 *       -I/usr/local/include -L/usr/local/lib -lndpi \
 *       -lpcap $(pkg-config --cflags --libs glib-2.0 2>/dev/null || echo '-lpthread -lm')
 *
 *   或直接链接已安装的 nDPI:
 *   gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c -lndpi -lpthread -lm
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>

/* ── 检测结果 ─────────────────────────────────────── */
typedef struct {
  uint16_t app_protocol;    /* 检测到的应用层协议 ID */
  uint16_t master_protocol; /* 隧道/承载层协议 ID */
  uint16_t protocol_by_ip;  /* 通过 IP 识别的协议 */
  uint16_t confidence;      /* 置信度: 0=unknown, 1=DPI, 2=guess */
} DetectionResult;

/* ── 引擎句柄 ─────────────────────────────────────── */
typedef struct {
  struct ndpi_detection_module_struct *ndpi_mod;
  size_t flow_size;
} DPIHandle;

/**
 * 初始化 DPI 引擎。
 * 返回句柄指针（作为 int64_t 传递）。
 */
int64_t ndpi_helper_init(void) {
  DPIHandle *h = calloc(1, sizeof(DPIHandle));
  if (!h) return 0;

  h->ndpi_mod = ndpi_init_detection_module(NULL);
  if (!h->ndpi_mod) { free(h); return 0; }

  if (ndpi_finalize_initialization(h->ndpi_mod) != 0) {
    ndpi_exit_detection_module(h->ndpi_mod);
    free(h);
    return 0;
  }

  h->flow_size = ndpi_detection_get_sizeof_ndpi_flow_struct();
  return (int64_t)(intptr_t)h;
}

/**
 * 创建新的 flow 结构。
 */
int64_t ndpi_helper_create_flow(int64_t handle) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  if (!h) return 0;

  struct ndpi_flow_struct *flow =
    (struct ndpi_flow_struct *)ndpi_flow_malloc(h->flow_size);
  if (!flow) return 0;

  memset(flow, 0, h->flow_size);
  return (int64_t)(intptr_t)flow;
}

/**
 * 释放 flow 结构。
 */
void ndpi_helper_free_flow(int64_t flow_ptr) {
  ndpi_flow_free((void *)(intptr_t)flow_ptr);
}

/**
 * 从 L2 帧中提取 L3 (IP) 载荷。
 * 支持 Ethernet II (0x0800 IPv4, 0x86DD IPv6)、802.1Q (0x8100) /
 * 802.1ad QinQ (0x88a8) VLAN 标签、以及 PPPoE Session (0x8864) 封装。
 * 运营商镜像(SPAN)流量常为 PPPoE，需跳过 PPPoE 头(6B) + PPP 协议(2B)。
 */
static int extract_l3(const uint8_t *l2_data, uint16_t l2_len,
                      const uint8_t **l3_data, uint16_t *l3_len) {
  if (!l2_data || l2_len < 14) return -1;
  uint16_t ethertype = (l2_data[12] << 8) | l2_data[13];

  /* 逐层跳过 VLAN 标签（每层 4 字节），直到真实 EtherType */
  while ((ethertype == 0x8100 || ethertype == 0x88a8) && l2_len >= 18) {
    l2_data += 4;
    l2_len -= 4;
    ethertype = (l2_data[12] << 8) | l2_data[13];
  }

  if (ethertype == 0x0800 || ethertype == 0x86DD) {
    *l3_data = l2_data + 14;
    *l3_len = l2_len - 14;
    return 0;
  }

  /* PPPoE Session: ethertype 0x8864，跳过 PPPoE 头(6B) + PPP 协议(2B) 到 IP */
  if (ethertype == 0x8864 && l2_len >= 22) {
    uint16_t ppp = (l2_data[20] << 8) | l2_data[21];
    if (ppp == 0x0021 || ppp == 0x0057) {  /* IPv4 / IPv6 */
      *l3_data = l2_data + 22;
      *l3_len = l2_len - 22;
      return 0;
    }
  }

  return -1;
}

/**
 * 处理一个数据包并返回应用层协议 ID。
 *
 * @param handle    DPI 引擎句柄
 * @param flow_ptr  flow 结构指针
 * @param data      原始二层数据包 (Ethernet 帧)
 * @param data_len  数据包长度
 * @param tick_ms   时间戳（毫秒）
 * @return 应用层协议 ID (NDPI_PROTOCOL_UNKNOWN=0 表示未检测到)
 */
uint16_t ndpi_helper_process(int64_t handle, int64_t flow_ptr,
                              const uint8_t *data, uint16_t data_len,
                              uint64_t tick_ms) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;

  if (!h || !flow) return 0;

  /* 提取 L3 (IP 层)，nDPI 需要从 IP 头开始解析 */
  const uint8_t *l3 = NULL;
  uint16_t l3_len = 0;
  if (extract_l3(data, data_len, &l3, &l3_len) != 0) return 0;

  ndpi_protocol p = ndpi_detection_process_packet(
      h->ndpi_mod, flow, l3, l3_len, tick_ms, NULL);

  /* 优先返回 app_protocol，其次尝试 protocol_stack */
  uint16_t proto = p.proto.app_protocol;
  if (proto == 0) proto = p.proto.master_protocol;
  if (proto == 0 && p.protocol_stack.protos_num > 0)
    proto = p.protocol_stack.protos[0];

  return proto;
}

/**
 * 强制 giveup 并返回应用层协议 ID。
 */
uint16_t ndpi_helper_giveup(int64_t handle, int64_t flow_ptr) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;

  if (!h || !flow) return 0;

  ndpi_protocol p = ndpi_detection_giveup(h->ndpi_mod, flow);

  uint16_t proto = p.proto.app_protocol;
  if (proto == 0) proto = p.proto.master_protocol;
  if (proto == 0 && p.protocol_stack.protos_num > 0)
    proto = p.protocol_stack.protos[0];

  return proto;
}

/**
 * 获取协议名称。
 */
const char *ndpi_helper_proto_name(int64_t handle, uint16_t proto_id) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  if (!h) return NULL;
  return ndpi_get_proto_name(h->ndpi_mod, proto_id);
}

/**
 * 获取协议分类名称。
 */
const char *ndpi_helper_category_name(int64_t handle,
                                      int64_t flow_ptr) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;
  if (!h || !flow) return NULL;
  ndpi_protocol_category_t cat = ndpi_get_flow_category(flow);
  return ndpi_category_get_name(h->ndpi_mod, cat);
}

/**
 * 获取协议分类 ID。
 */
uint16_t ndpi_helper_category_id(int64_t handle,
                                  int64_t flow_ptr) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;
  if (!h || !flow) return NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;
  return (uint16_t)ndpi_get_flow_category(flow);
}

/* ── 风险检测 ─────────────────────────────────────── */

/**
 * 返回流中检测到的风险位图 (bitmask of ndpi_risk_enum)。
 */
uint64_t ndpi_helper_get_risk_bitmap(int64_t flow_ptr) {
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;
  if (!flow) return 0;
  return (uint64_t)flow->risk;
}

/**
 * 返回风险详情条目数。
 */
int ndpi_helper_get_risk_info_count(int64_t flow_ptr) {
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;
  if (!flow) return 0;
  return (int)flow->num_risk_infos;
}

/**
 * 获取第 index 条风险详情。
 * @param flow_ptr   flow 结构指针
 * @param index      索引 (0-based)
 * @param out_id     输出: 风险 ID (ndpi_risk_enum)
 * @param out_info   输出: 风险描述文本 (预分配缓冲区)
 * @param info_size  缓冲区大小
 */
void ndpi_helper_get_risk_info_at(int64_t flow_ptr, int index,
                                   uint16_t *out_id, char *out_info, int info_size) {
  struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)(intptr_t)flow_ptr;
  if (!flow || index < 0 || index >= (int)flow->num_risk_infos) {
    if (out_id) *out_id = 0;
    if (out_info && info_size > 0) out_info[0] = '\0';
    return;
  }
  if (out_id) *out_id = (uint16_t)flow->risk_infos[index].id;
  if (out_info && info_size > 0) {
    if (flow->risk_infos[index].info) {
      strncpy(out_info, flow->risk_infos[index].info, info_size - 1);
      out_info[info_size - 1] = '\0';
    } else {
      out_info[0] = '\0';
    }
  }
}

/**
 * 返回风险枚举对应的可读名称。
 * 例如 NDPI_TLS_SELFSIGNED_CERTIFICATE → "TLS Self-Signed Certificate"
 */
const char *ndpi_helper_risk_name(uint16_t risk_id) {
  return ndpi_risk2str((ndpi_risk_enum)risk_id);
}

/**
 * 返回风险严重级别 (0=low .. 5=emergency)。
 */
int ndpi_helper_risk_severity(uint16_t risk_id) {
  ndpi_risk_info *ri = ndpi_risk2severity((ndpi_risk_enum)risk_id);
  if (!ri) return 0;
  return (int)ri->severity;
}

/**
 * 返回严重级别名称。
 */
const char *ndpi_helper_severity_name(int severity) {
  return ndpi_severity2str((ndpi_risk_severity)severity);
}

/**
 * 销毁 DPI 引擎。
 */
void ndpi_helper_destroy(int64_t handle) {
  DPIHandle *h = (DPIHandle *)(intptr_t)handle;
  if (!h) return;
  if (h->ndpi_mod) ndpi_exit_detection_module(h->ndpi_mod);
  free(h);
}
