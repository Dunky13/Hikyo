export const repositoryUrl = 'https://github.com/Hikyo-Org/hikyo';
export const themeStorageKey = 'hikyo-theme';

export const siteBase = import.meta.env.BASE_URL === '/'
  ? ''
  : import.meta.env.BASE_URL.replace(/\/$/, '');

export const fumadocsBase = siteBase || '/';

export function siteUrl(path = ''): string {
  return `${siteBase}/${path.replace(/^\//, '')}`;
}

export const themeBootstrapScript = `(() => {
  const theme = localStorage.getItem(${JSON.stringify(themeStorageKey)});
  const dark = theme !== 'light';
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
})();`;
