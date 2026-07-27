/** 国家代码 → 中文名称映射 + 国旗 Emoji */

const countryNames: Record<string, string> = {
  US: '美国', CN: '中国', JP: '日本', KR: '韩国', TW: '台湾',
  HK: '香港', MO: '澳门', SG: '新加坡', MY: '马来西亚', ID: '印尼',
  PH: '菲律宾', TH: '泰国', VN: '越南', IN: '印度', PK: '巴基斯坦',
  BD: '孟加拉', NP: '尼泊尔', LK: '斯里兰卡', MM: '缅甸', KH: '柬埔寨',
  LA: '老挝', MN: '蒙古', RU: '俄罗斯', GB: '英国', DE: '德国',
  FR: '法国', IT: '意大利', ES: '西班牙', NL: '荷兰', BE: '比利时',
  CH: '瑞士', AT: '奥地利', SE: '瑞典', NO: '挪威', DK: '丹麦',
  FI: '芬兰', PL: '波兰', CZ: '捷克', SK: '斯洛伐克', HU: '匈牙利',
  RO: '罗马尼亚', BG: '保加利亚', GR: '希腊', PT: '葡萄牙', IE: '爱尔兰',
  UA: '乌克兰', BY: '白俄罗斯', TR: '土耳其', IL: '以色列', AE: '阿联酋',
  SA: '沙特', QA: '卡塔尔', KW: '科威特', IR: '伊朗', IQ: '伊拉克',
  EG: '埃及', ZA: '南非', NG: '尼日利亚', KE: '肯尼亚', AU: '澳大利亚',
  NZ: '新西兰', CA: '加拿大', MX: '墨西哥', BR: '巴西', AR: '阿根廷',
  CL: '智利', CO: '哥伦比亚', PE: '秘鲁', VE: '委内瑞拉', CU: '古巴',
  EU: '欧洲', AP: '亚太', AN: '荷兰安地列斯',
  O1: '其他地区', A1: '匿名代理', A2: '卫星提供商',
}

/** 根据 ISO 3166-1 alpha-2 国家代码获取国旗 Emoji */
export function countryFlag(code: string): string {
  if (!code || code.length !== 2) return '🏳'
  const base = 0x1F1E6
  return String.fromCodePoint(
    base + (code.charCodeAt(0) - 65),
    base + (code.charCodeAt(1) - 65),
  )
}

/** 根据国家代码获取中文名称 */
export function countryName(code: string): string {
  return countryNames[code.toUpperCase()] || code
}
