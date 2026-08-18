"use client";

import Link from "next/link";
import Image from "next/image";
import { useState, FormEvent, useCallback, useEffect } from "react";
import { useTranslations } from 'next-intl';
import { convertSubscription, SubResponseData, ErrorData, createShortUrl, ShortUrlData, getAvailableDownloads, detectUserOS, AppDownloadInfo } from '@/lib/api-client';
import LanguageSwitcher from '@/components/LanguageSwitcher';
import { copyToClipboard } from '@/lib/clipboard';

// Define config presets for easy maintenance
const CONFIG_PRESETS = [
  {
    name: "ACL4SSR",
    url: "/config/ACL4SSR.ini",
    description: "Basic rules"
  },
  {
    name: "ACL4SSR Full",
    url: "/config/ACL4SSR_Online_Full.ini",
    description: "Full rules"
  },
  {
    name: "ACL4SSR Mini",
    url: "/config/ACL4SSR_Online_Mini.ini",
    description: "Minimal rules"
  },
  {
    name: "Divine China",
    url: "/config/China.yaml",
    description: "China rules"
  },
  {
    name: "Loon Simple",
    url: "/config/loon_simple.conf",
    description: "Simple Loon config"
  }
];

export default function Home() {
  const t = useTranslations('HomePage');

  const [subscriptionUrl, setSubscriptionUrl] = useState("");
  const [targetFormat, setTargetFormat] = useState("clash");
  const [configUrl, setConfigUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<SubResponseData | null>(null);
  const [error, setError] = useState<ErrorData | null>(null);
  const [saveApiUrl, setSaveApiUrl] = useState(true);
  const [shortUrlCreating, setShortUrlCreating] = useState(false);
  const [shortUrlCreated, setShortUrlCreated] = useState(false);
  const [shortUrlData, setShortUrlData] = useState<ShortUrlData | null>(null);
  const [userOs, setUserOs] = useState<string>("");
  const [downloads, setDownloads] = useState<AppDownloadInfo[]>([]);
  const [downloadLoading, setDownloadLoading] = useState(false);

  // Detect user OS
  useEffect(() => {
    setUserOs(detectUserOS());
  }, []);

  // Fetch available downloads
  useEffect(() => {
    async function fetchDownloads() {
      try {
        setDownloadLoading(true);
        const downloadList = await getAvailableDownloads();
        setDownloads(downloadList);
      } catch (err) {
        console.error("Error fetching downloads:", err);
      } finally {
        setDownloadLoading(false);
      }
    }

    fetchDownloads();
  }, []);

  // Reset shortUrlCreated when form inputs change
  useEffect(() => {
    setShortUrlCreated(false);
  }, [subscriptionUrl, targetFormat, configUrl]);

  // Generate the API URL based on form inputs
  const generateApiUrl = useCallback(() => {
    const baseUrl = window.location.origin + '/api/sub';
    const params = new URLSearchParams();
    params.append('target', targetFormat);
    params.append('url', subscriptionUrl);

    // Add config if set
    if (configUrl) {
      params.append('config', configUrl);
    }

    return `${baseUrl}?${params.toString()}`;
  }, [targetFormat, subscriptionUrl, configUrl]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!subscriptionUrl) return;

    setIsLoading(true);
    setResult(null);
    setError(null);
    setShortUrlCreated(false);

    try {
      // Call the actual conversion API
      const payload: any = {
        target: targetFormat,
        url: subscriptionUrl
      };

      // Add config if set
      if (configUrl) {
        payload.config = configUrl;
      }

      const responseData = await convertSubscription(payload);
      setResult(responseData);

      // If saveApiUrl is enabled, create a short URL
      if (saveApiUrl) {
        await createShortUrlForConversion();
      }
    } catch (err) {
      console.error("Conversion API call failed:", err);
      setError(err as ErrorData || {
        error: 'Failed to connect to the conversion API.',
        details: String(err)
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Create a short URL for the current subscription
  const createShortUrlForConversion = async () => {
    if (!subscriptionUrl) return;

    try {
      setShortUrlCreating(true);
      const apiUrl = generateApiUrl();
      const description = `${targetFormat.toUpperCase()} subscription for ${subscriptionUrl.substring(0, 30)}${subscriptionUrl.length > 30 ? '...' : ''}`;

      const shortUrl = await createShortUrl({
        target_url: apiUrl,
        description: description
      });

      setShortUrlData(shortUrl);
      setShortUrlCreated(true);
    } catch (err) {
      console.error("Error creating short URL:", err);
      // We don't show this error to the user to avoid confusion
      // The main conversion still succeeded
    } finally {
      setShortUrlCreating(false);
    }
  };

  const handleDownload = useCallback(() => {
    if (!result || !result.content) return;

    const blob = new Blob([result.content], { type: result.content_type || 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `config.${targetFormat === 'clash' ? 'yaml' : 'txt'}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, [result, targetFormat]);

  // The supported target formats from the convert page
  const SUPPORTED_TARGETS = [
    'clash', 'singbox', 'surge', 'quan', 'quanx',
    'mellow', 'surfboard', 'loon', 'ss', 'ssr', 'sssub',
    'v2ray', 'trojan', 'trojan-go', 'hysteria', 'hysteria2',
    'ssd', 'mixed', 'clashr'
  ];

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-4 md:p-8 lg:p-24">
      <div className="z-10 max-w-5xl w-full items-center justify-between font-mono text-sm">
        <div className="flex flex-col sm:flex-row items-center justify-between mb-6">
          <div className="flex items-center gap-4 mb-4 sm:mb-0">
            <Image src="/logo.svg" alt="Subconverter Logo" width={60} height={60} />
            <h1 className="text-4xl font-bold text-center">{t('title')}</h1>
          </div>
          <div className="flex gap-4 items-center">
            <LanguageSwitcher />
            <a
              href="https://github.com/lonelam/subconverter-rs"
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white px-4 py-2 rounded-lg transition-all duration-300 ease-in-out shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 flex flex-col items-center text-center w-50"
            >
              <div className="flex items-center gap-2 mb-1">
                <svg className="w-5 h-5 group-hover:scale-110 transition-transform" height="24" width="24" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path>
                </svg>
                <span className="font-semibold">{t('githubStar')}</span>
              </div>
              <p className="text-xs text-indigo-100 group-hover:text-white transition-colors">
                {t('selfHostPrompt')}
              </p>
            </a>
          </div>
        </div>

        <div className="bg-white/5 p-6 rounded-lg shadow-md mb-8">
          <h2 className="text-2xl font-semibold mb-4">{t('quickConvert')}</h2>
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div>
              <label htmlFor="subscriptionUrl" className="block text-sm font-medium mb-1">
                {t('subscriptionUrl')}
              </label>
              <input
                type="url"
                id="subscriptionUrl"
                placeholder="https://example.com/subscription"
                className="w-full p-2 border border-gray-300 rounded bg-white/10"
                value={subscriptionUrl}
                onChange={(e) => setSubscriptionUrl(e.target.value)}
                required
              />
            </div>

            <div>
              <label htmlFor="targetFormat" className="block text-sm font-medium mb-1">
                {t('targetFormat')}
              </label>
              <select
                id="targetFormat"
                className="w-full p-2 border border-gray-300 rounded bg-white/10"
                value={targetFormat}
                onChange={(e) => setTargetFormat(e.target.value)}
              >
                {SUPPORTED_TARGETS.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>

            <div>
              <label htmlFor="configUrl" className="block text-sm font-medium mb-1">
                {t('externalConfig')}
              </label>
              <div className="flex flex-wrap gap-2 mb-2">
                {CONFIG_PRESETS.map(preset => (
                  <button
                    key={preset.name}
                    type="button"
                    onClick={() => setConfigUrl(preset.url)}
                    className={`px-3 py-1.5 text-xs rounded border transition-colors ${configUrl === preset.url
                      ? 'bg-blue-500 text-white border-blue-600'
                      : 'bg-blue-100 hover:bg-blue-200 border-blue-300 text-blue-800'
                      }`}
                    title={preset.description}
                  >
                    {preset.name}
                  </button>
                ))}
              </div>
              <input
                type="text"
                id="configUrl"
                placeholder="External configuration URL or path"
                className="w-full p-2 border border-gray-300 rounded bg-white/10"
                value={configUrl}
                onChange={(e) => setConfigUrl(e.target.value)}
              />
              <p className="mt-1 text-xs text-gray-400">
                {t('optionalConfigInfo')}
              </p>
            </div>

            <div className="flex items-center">
              <input
                id="saveApiUrl"
                type="checkbox"
                checked={saveApiUrl}
                onChange={(e) => setSaveApiUrl(e.target.checked)}
                className="h-4 w-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500"
              />
              <label htmlFor="saveApiUrl" className="ml-2 text-sm">
                {t('saveAsSubscription')}
              </label>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50"
            >
              {isLoading ? t('converting') : t('convert')}
            </button>
          </form>

          {error && (
            <div className="mt-6 p-4 border border-red-400 bg-red-50 rounded-md">
              <h3 className="text-lg font-semibold text-red-800">{t('error')}</h3>
              <p className="text-red-700">{error.error}</p>
              {error.details && <p className="mt-1 text-sm text-red-600">{error.details}</p>}
              <p className="mt-2 text-sm text-gray-700">
                {t('reportIssuePrompt')}
                {' '}
                <a
                  href="https://github.com/lonelam/subconverter-rs/issues/new/choose"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  {t('createIssueLinkText')}
                </a>
                . {t('pasteErrorInfo')}
              </p>
            </div>
          )}

          {result && !error && (
            <div className="mt-6">
              {/* API URL Display */}
              <div className="mb-4 p-3 bg-white/10 border border-gray-300 rounded-md">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="font-medium">{t('subscriptionUrlDisplay')}</h4>
                  <button
                    onClick={() => copyToClipboard(shortUrlData && shortUrlCreated ? shortUrlData.short_url : generateApiUrl())}
                    className="text-xs px-2 py-1 bg-gray-600 hover:bg-gray-700 text-white rounded"
                  >
                    {t('copy')}
                  </button>
                </div>
                <p className="text-xs break-all font-mono bg-gray-800 p-2 rounded text-white">
                  {shortUrlData && shortUrlCreated ? shortUrlData.short_url : generateApiUrl()}
                </p>
                <p className="text-xs mt-1">
                  <span className="text-gray-400">
                    {t('useUrlMessage')}
                  </span>
                  <span className="text-gray-400">
                    {saveApiUrl && !shortUrlCreated && t('urlWillBeSaved')}
                  </span>
                  <span className="text-gray-400">
                    {shortUrlCreated && t('shortUrlMessage')}
                  </span>
                </p>
              </div>

              {/* Result preview */}
              <div className="mt-4">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="font-medium">{t('previewTitle')}</h4>
                  <div className="text-xs text-gray-400">Content-Type: {result.content_type}</div>
                </div>
                <textarea
                  readOnly
                  value={result.content}
                  rows={8}
                  className="w-full p-2 bg-gray-800 rounded font-mono text-sm text-white"
                />
                <div className="mt-2 flex justify-end">
                  <button
                    onClick={handleDownload}
                    className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
                  >
                    {t('downloadConfig')}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white/5 p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold mb-4">{t('advancedConvert')}</h2>
            <p className="mb-4">
              {t('advancedDescription')}
            </p>
            <Link
              href="/convert"
              className="block bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded text-center"
            >
              {t('advancedOptions')}
            </Link>
          </div>

          <div className={`bg-white/5 p-6 rounded-lg shadow-md ${result && (saveApiUrl || shortUrlCreated) ? 'border-2 border-green-500 bg-white/10' : ''}`}>
            <h2 className="text-2xl font-semibold mb-4">{t('mySavedLinks')}</h2>
            <p className="mb-4">
              {t('savedLinksDescription')}
              {shortUrlCreating && (
                <span className="block mt-2 text-blue-400 text-sm">
                  {t('creatingShortUrl')}
                </span>
              )}
              {shortUrlCreated && (
                <span className="block mt-2 text-green-400 text-sm">
                  {t('shortUrlCreated')}
                </span>
              )}
            </p>
            <Link
              href="/links"
              className={`block ${result && (saveApiUrl || shortUrlCreated) ? 'bg-green-500' : 'bg-green-600'} hover:bg-green-700 text-white font-bold py-2 px-4 rounded text-center ${result && (saveApiUrl || shortUrlCreated) ? 'animate-pulse' : ''}`}
            >
              {t('manageLinks')}
            </Link>
          </div>

          <div className="bg-white/5 p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold mb-4">{t('serverSettings')}</h2>
            <div className="flex items-center mb-4">
              <svg className="w-6 h-6 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
              </svg>
              <p>{t('serverSettingsDescription')}</p>
            </div>
            <Link
              href="/settings"
              className="block bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-center"
            >
              {t('manageSettings')}
            </Link>
          </div>

          <div className="bg-white/5 p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold mb-4">{t('appDownloads')}</h2>
            <p className="mb-4">
              {t('appDownloadsDescription')}
            </p>
            <div className="flex gap-3">
              {userOs !== "unknown" && (
                downloadLoading ? (
                  <div className="flex-1 py-3 text-center">{t('loadingDownloads')}</div>
                ) : (
                  downloads.find(d => d.platform === userOs) ? (
                    <a
                      href={downloads.find(d => d.platform === userOs)?.download_url}
                      className="flex-1 bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded text-center flex items-center justify-center"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path>
                      </svg>
                      {t('downloadFor', { os: userOs.charAt(0).toUpperCase() + userOs.slice(1) })}
                    </a>
                  ) : (
                    <div className="flex-1 py-3 text-center">{t('noDownloadAvailable', { os: userOs })}</div>
                  )
                )
              )}
              <Link
                href="/downloads"
                className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded text-center"
              >
                {t('allDownloads')}
              </Link>
            </div>
          </div>
        </div>
      </div>

      <footer className="w-full text-center mt-16 text-sm text-gray-400">
        <p>
          {t('footer')}
        </p>
      </footer>
    </main>
  );
}
