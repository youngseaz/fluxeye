/* 独立测试：直接调用 nDPI 检测 pcap */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>

int main() {
  struct ndpi_detection_module_struct *mod;
  struct ndpi_flow_struct *flow;
  size_t flow_size;

  /* Init */
  mod = ndpi_init_detection_module(NULL);
  if (!mod) { printf("init failed\n"); return 1; }
  if (ndpi_finalize_initialization(mod) != 0) { printf("finalize failed\n"); return 1; }

  flow_size = ndpi_detection_get_sizeof_ndpi_flow_struct();
  printf("Flow size: %zu\n", flow_size);

  /* Create flow */
  flow = ndpi_flow_malloc(flow_size);
  memset(flow, 0, flow_size);

  /* Build a simple HTTP GET packet */
  unsigned char pkt[] = {
    /* Ethernet */
    0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,
    0x08,0x00,
    /* IPv4: ver=4,ihl=5, len=20+20+59=99, id=0, frag=0, ttl=64, proto=TCP,
       cksum=0, src=10.0.0.1, dst=93.184.216.34 */
    0x45, 0x00, 0x00, 99, 0x00, 0x00, 0x40, 0x06, 0x00,
    0x0a,0x00,0x00,0x01, 0x5d,0xb8,0xd8,0x22,
    /* TCP: sport=40000, dport=80, seq=1, ack=1, offset=5, flags=PSH+ACK,
       window=0, cksum=0, urp=0 */
    0x9c,0x40, 0x00,0x50, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01,
    0x50,0x18, 0x00,0x00, 0x00,0x00, 0x00,0x00,
    /* HTTP GET */
    'G','E','T',' ','/',' ','H','T','T','P','/','1','.','1','\r','\n',
    'H','o','s','t',':',' ','a','\r','\n','\r','\n'
  };
  int pkt_len = 14 + 20 + 20 + 29; /* eth + ip + tcp + payload */

  /* Update the IP total length field */
  pkt[16] = (20 + 20 + 29) >> 8;
  pkt[17] = (20 + 20 + 29) & 0xff;

  printf("Packet len: %d\n", pkt_len);

  /* Process the packet */
  ndpi_protocol result = ndpi_detection_process_packet(mod, flow, pkt, pkt_len, 0, NULL);

  printf("After process_packet:\n");
  printf("  app_protocol: %d\n", result.proto.app_protocol);
  printf("  master_protocol: %d\n", result.proto.master_protocol);
  printf("  protocol_by_ip: %d\n", result.protocol_by_ip);
  printf("  state: %d\n", (int)result.state);

  /* Check flow struct directly */
  printf("  flow->detected_protocol_stack[0]: %d\n", flow->detected_protocol_stack[0]);

  /* Try giveup */
  result = ndpi_detection_giveup(mod, flow);
  printf("\nAfter giveup:\n");
  printf("  app_protocol: %d\n", result.proto.app_protocol);
  printf("  master_protocol: %d\n", result.proto.master_protocol);
  printf("  protocol_by_ip: %d\n", result.protocol_by_ip);
  printf("  state: %d\n", (int)result.state);
  printf("  flow->detected_protocol_stack[0]: %d\n", flow->detected_protocol_stack[0]);

  if (result.proto.app_protocol) {
    const char *name = ndpi_get_proto_name(mod, result.proto.app_protocol);
    printf("  name: %s\n", name ? name : "?");
    printf("\n✅ nDPI DPI 检测成功!\n");
  } else {
    printf("\n❌ nDPI 未检测到协议\n");
  }

  ndpi_flow_free(flow);
  ndpi_exit_detection_module(mod);
  return 0;
}
