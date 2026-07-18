import type { ThemeConfig } from 'antd';

// RelayPanel — "薄雾青绿 / Mist + Teal" theme.
// All-light chrome (white sidebar + header, near-white canvas) with a single
// restrained teal accent. Token-driven: every antd component (buttons, tables,
// tags, inputs, menu…) picks this up via ConfigProvider, so individual
// components stay untouched. Layout chrome + custom elements live in
// styles/theme.css, which mirrors these values as CSS variables.
//
// Palette anchors (keep in sync with theme.css :root):
//   teal   600 #0d9488  700 #0f766e  50 #f0fdfa  200 #99f6e4
//   canvas #f6f7f9   card #ffffff   hairline #ecedf1   border #dfe3e8
//   text   #101828 / #5a6472 / #98a2b3
export const rpTheme: ThemeConfig = {
  token: {
    colorPrimary: '#0d9488',
    colorInfo: '#0891b2',
    colorSuccess: '#16a34a',
    colorWarning: '#d97706',
    colorError: '#dc2626',
    colorLink: '#0f766e',
    colorLinkHover: '#0d9488',

    colorText: '#101828',
    colorTextSecondary: '#5a6472',
    colorTextTertiary: '#98a2b3',
    colorTextQuaternary: '#b6bec9',

    colorBgLayout: '#f6f7f9',
    colorBorder: '#dfe3e8',
    colorBorderSecondary: '#ecedf1',

    borderRadius: 8,
    borderRadiusLG: 12,
    borderRadiusSM: 6,

    // Roomier controls than antd's 32px default — the admin forms and toolbars
    // read as cramped at 32 once the sidebar goes light.
    controlHeight: 36,

    fontSize: 14,
    fontWeightStrong: 600,
    lineHeight: 1.5715,
    fontFamily:
      '"Noto Sans SC", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", ' +
      '"PingFang SC", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif',

    // Flatter, wider-spread shadows than antd's defaults — the light chrome
    // relies on hairlines for separation, not drop shadows.
    boxShadow: '0 4px 12px rgba(16, 24, 40, 0.07)',
    boxShadowSecondary: '0 8px 24px rgba(16, 24, 40, 0.10)',
    boxShadowTertiary: '0 1px 2px rgba(16, 24, 40, 0.05)',
  },
  components: {
    // Light sidebar: pill-shaped items inset from the edges, teal-tinted
    // selection instead of antd's solid blue bar.
    Menu: {
      itemBg: 'transparent',
      subMenuItemBg: 'transparent',
      itemColor: '#5a6472',
      itemHoverColor: '#101828',
      itemHoverBg: '#f2f4f6',
      itemSelectedBg: '#f0fdfa',
      itemSelectedColor: '#0f766e',
      itemActiveBg: '#e6fbf7',
      itemHeight: 40,
      itemMarginInline: 10,
      itemMarginBlock: 2,
      itemBorderRadius: 8,
      iconSize: 16,
      collapsedIconSize: 18,
      groupTitleColor: '#98a2b3',
      groupTitleFontSize: 11,
    },
    // Flat buttons — drop antd's default control shadow for a cleaner look.
    Button: {
      primaryShadow: 'none',
      defaultShadow: 'none',
      dangerShadow: 'none',
      fontWeight: 500,
      paddingInline: 16,
    },
    Card: {
      borderRadiusLG: 12,
      headerBg: 'transparent',
      headerHeight: 52,
      headerFontSize: 15,
      paddingLG: 20,
      boxShadowTertiary: '0 1px 2px rgba(16, 24, 40, 0.05)',
    },
    Table: {
      headerBg: '#fafbfc',
      headerColor: '#5a6472',
      headerSplitColor: 'transparent',
      rowHoverBg: '#f5faf9',
      borderColor: '#ecedf1',
      cellPaddingBlock: 12,
      cellPaddingBlockSM: 10,
      footerBg: 'transparent',
    },
    Layout: {
      bodyBg: '#f6f7f9',
      headerBg: '#ffffff',
      siderBg: '#ffffff',
      headerPadding: '0 20px',
    },
    Tag: {
      borderRadiusSM: 6,
      defaultBg: '#f2f4f6',
      defaultColor: '#5a6472',
    },
    Modal: {
      borderRadiusLG: 14,
      headerBg: 'transparent',
      titleFontSize: 16,
    },
    Segmented: {
      trackBg: '#f2f4f6',
      itemSelectedBg: '#ffffff',
      itemSelectedColor: '#0f766e',
      borderRadius: 8,
      borderRadiusSM: 6,
    },
    Statistic: {
      contentFontSize: 28,
      titleFontSize: 13,
    },
    Input: {
      paddingInline: 12,
    },
    Select: {
      optionSelectedBg: '#f0fdfa',
      optionSelectedColor: '#0f766e',
    },
    Alert: {
      borderRadiusLG: 10,
      defaultPadding: '10px 14px',
      withDescriptionPadding: '14px 16px',
    },
    Drawer: {
      paddingLG: 20,
    },
    Tabs: {
      itemSelectedColor: '#0f766e',
      itemHoverColor: '#0d9488',
      inkBarColor: '#0d9488',
      horizontalMargin: '0 0 16px 0',
    },
    Descriptions: {
      labelBg: '#fafbfc',
      titleMarginBottom: 12,
    },
    Progress: {
      defaultColor: '#0d9488',
    },
    Switch: {
      handleShadow: '0 1px 2px rgba(16, 24, 40, 0.16)',
    },
    Tooltip: {
      colorBgSpotlight: '#1f2937',
      borderRadius: 8,
    },
    Pagination: {
      itemActiveBg: '#f0fdfa',
    },
  },
};
