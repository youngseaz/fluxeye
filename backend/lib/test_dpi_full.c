#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>

/* 构造一个带完整 TCP 握手 + HTTP 请求的测试 */
int main() {
  struct ndpi_detection_module_struct *mod;
  struct ndpi_flow_struct *flow;
  size_t flow_size;

  mod = ndpi_init_detection_module(NULL);
  ndpi_finalize_initialization(mod);
  flow_size = ndpi_detection_get_sizeof_ndpi_flow_struct();
  flow = ndpi_flow_malloc(flow_size);
  memset(flow, 0, flow_size);

  /* 4 packets: SYN, SYN-ACK, ACK, GET */
  unsigned char syn[] = {
    0,0,0,0,0,0, 0,0,0,0,0,0, 0x08,0x00,
    0x45,0,0,0x28,0,0,0x40,6,0, 10,0,0,1, 93,184,216,34,
    0x9c,0x40, 0x00,0x50, 0,0,0,0, 0,0,0,0, 0x50,0x02,0,0, 0,0,0,0
  };
  unsigned char synack[] = {
    0,0,0,0,0,0, 0,0,0,0,0,0, 0x08,0x00,
    0x45,0,0,0x28,0,0,0x40,6,0, 93,184,216,34, 10,0,0,1,
    0x00,0x50, 0x9c,0x40, 0,0,0,1, 0,0,0,1, 0x50,0x12,0,0, 0,0,0,0
  };
  unsigned char ack[] = {
    0,0,0,0,0,0, 0,0,0,0,0,0, 0x08,0x00,
    0x45,0,0,0x28,0,0,0x40,6,0, 10,0,0,1, 93,184,216,34,
    0x9c,0x40, 0x00,0x50, 0,0,0,1, 0,0,0,1, 0x50,0x10,0,0, 0,0,0,0
  };
  char *get_req = "GET / HTTP/1.1\r\nHost: test.com\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n";
  int get_len = strlen(get_req);
  unsigned char getpkt[14+20+20+1024];
  memcpy(getpkt, syn, 14+20);
  memcpy(getpkt+14+20, ack+14+20, 20);
  getpkt[14+20+12] = 0x50 | 0x08; /* PSH + ACK */
  memcpy(getpkt+14+20+20, get_req, get_len);
  int ip_total = 20+20+get_len;
  getpkt[16] = ip_total >> 8; getpkt[17] = ip_total & 0xff;

  unsigned char *packets[] = {syn, synack, ack, getpkt};
  int lens[] = {14+20+20, 14+20+20, 14+20+20, 14+20+20+get_len};

  for (int i = 0; i < 4; i++) {
    ndpi_protocol r = ndpi_detection_process_packet(mod, flow, packets[i], lens[i], i*1000, NULL);
    printf("包%d: app=%d master=%d state=%d stack0=%d\n",
           i+1, r.proto.app_protocol, r.proto.master_protocol,
           (int)r.state, flow->detected_protocol_stack[0]);
    if (i == 3) {
      r = ndpi_detection_giveup(mod, flow);
      printf("giveup: app=%d master=%d state=%d stack0=%d\n",
             r.proto.app_protocol, r.proto.master_protocol,
             (int)r.state, flow->detected_protocol_stack[0]);
      if (r.proto.app_protocol) {
        printf("协议: %s\n", ndpi_get_proto_name(mod, r.proto.app_protocol));
        printf("✅ DPI 检测成功!\n");
      } else {
        printf("❌ 未检测到\n");
      }
    }
  }

  ndpi_flow_free(flow);
  ndpi_exit_detection_module(mod);
  return 0;
}
