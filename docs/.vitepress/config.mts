import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'zh-CN',
  title: 'RelayPanel 使用指南',
  description: 'RelayPanel 自托管 TCP/UDP 端口转发管理面板的安装、配置、升级与排障指南。',
  base: '/relay-panel/',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: [
    'internal/**',
    'ROADMAP-v0.4.md',
    'VERSIONS.md',
    'repo-test-parity.md',
  ],
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/relay-panel/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#0f766e' }],
    ['meta', { name: 'color-scheme', content: 'light dark' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'RelayPanel 使用指南' }],
    ['meta', {
      property: 'og:description',
      content: '从安装、节点接入到多跳、UOT、TCP 0-RTT 和安全升级。',
    }],
    ['meta', {
      property: 'og:image',
      content: 'https://aict666.github.io/relay-panel/og-relaypanel.png',
    }],
    ['meta', { property: 'og:image:width', content: '1200' }],
    ['meta', { property: 'og:image:height', content: '630' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
  ],
  markdown: {
    lineNumbers: true,
  },
  themeConfig: {
    siteTitle: 'RelayPanel 指南',
    logo: {
      src: '/logo.svg',
      alt: 'RelayPanel',
    },
    nav: [
      { text: '首页', link: '/' },
      { text: '快速开始', link: '/guide/quick-start' },
      { text: '使用指南', link: '/guide/concepts' },
      { text: '高级路由', link: '/ADVANCED-ROUTING-UOT' },
      { text: 'GitHub', link: 'https://github.com/aict666/relay-panel' },
    ],
    sidebar: [
      {
        text: '开始使用',
        items: [
          { text: '快速开始', link: '/guide/quick-start' },
          { text: '核心概念', link: '/guide/concepts' },
          { text: '创建转发规则', link: '/guide/rules' },
          { text: '预设隧道与端口复用', link: '/guide/tunnels' },
        ],
      },
      {
        text: '部署与运维',
        items: [
          { text: '节点安装与管理', link: '/NODE.zh-CN' },
          { text: '安全配置', link: '/guide/security' },
          { text: '安全升级与回滚', link: '/guide/upgrade' },
          { text: '故障排查', link: '/guide/troubleshooting' },
          { text: '反向代理', link: '/REVERSE-PROXY' },
          { text: '简化 TLS 部署', link: '/TLS-SIMPLE' },
        ],
      },
      {
        text: '高级功能',
        items: [
          { text: '高级路由、UOT 与 0-RTT', link: '/ADVANCED-ROUTING-UOT' },
          { text: '完整部署参考', link: '/DEPLOYMENT' },
          { text: '免责声明', link: '/DISCLAIMER' },
        ],
      },
    ],
    outline: {
      level: [2, 3],
      label: '本页目录',
    },
    docFooter: {
      prev: '上一篇',
      next: '下一篇',
    },
    lastUpdated: {
      text: '最后更新',
      formatOptions: {
        dateStyle: 'medium',
        timeStyle: 'short',
      },
    },
    editLink: {
      pattern: 'https://github.com/aict666/relay-panel/edit/main/docs/:path',
      text: '在 GitHub 上编辑此页',
    },
    search: {
      provider: 'local',
      options: {
        translations: {
          button: {
            buttonText: '搜索文档',
            buttonAriaLabel: '搜索文档',
          },
          modal: {
            noResultsText: '没有找到相关内容',
            resetButtonTitle: '清除查询条件',
            footer: {
              selectText: '选择',
              navigateText: '切换',
              closeText: '关闭',
            },
          },
        },
      },
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/aict666/relay-panel' },
    ],
    footer: {
      message: '基于 AGPL-3.0 许可证开源',
      copyright: 'RelayPanel 使用指南',
    },
  },
})
