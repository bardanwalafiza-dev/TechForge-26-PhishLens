/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Menu,
  Globe,
  CreditCard,
  FileText,
  Camera,
  Upload,
  Languages,
  Archive,
  Sparkles,
  Shield,
  ChevronDown,
  X,
  CheckCircle2,
} from 'lucide-react';
import { analyzeTarget, ThreatAnalysisResult } from './lib/engine.ts';
import { TRANSLATIONS, LANGUAGE_OPTIONS, LanguageCode } from './lib/translations.ts';
import { QrCameraScanner } from './components/QrCameraScanner.tsx';
import { ImageQrUploader } from './components/ImageQrUploader.tsx';
import { ResultModal } from './components/ResultModal.tsx';
import { HistoryGuidelinesSidebar } from './components/HistoryGuidelinesSidebar.tsx';
import { PhishLensLogo } from './components/PhishLensLogo.tsx';
import { exportSoftwareZip } from './lib/zipExporter.ts';

type NavTab = 'link' | 'upi' | 'kyc' | 'scan-qr' | 'upload';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('link');
  const [urlInput, setUrlInput] = useState<string>('');
  const [scanResult, setScanResult] = useState<ThreatAnalysisResult | null>(null);
  const [isResultModalOpen, setIsResultModalOpen] = useState<boolean>(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState<boolean>(false);
  
  // Persisted language state with 18 languages support
  const [currentLanguage, setCurrentLanguage] = useState<LanguageCode>(() => {
    try {
      const stored = sessionStorage.getItem('phishlens_lang') as LanguageCode;
      if (stored && TRANSLATIONS[stored]) return stored;
    } catch {
      // safe fallback
    }
    return 'en';
  });

  const [showLanguageDropdown, setShowLanguageDropdown] = useState<boolean>(false);
  const [isZipping, setIsZipping] = useState<boolean>(false);

  // Scan History
  const [scanHistory, setScanHistory] = useState<ThreatAnalysisResult[]>(() => {
    try {
      const stored = sessionStorage.getItem('phishlens_audit_history');
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });

  const t = TRANSLATIONS[currentLanguage] || TRANSLATIONS.en;

  const handleLanguageChange = (code: LanguageCode) => {
    setCurrentLanguage(code);
    setShowLanguageDropdown(false);
    try {
      sessionStorage.setItem('phishlens_lang', code);
    } catch {
      // safe
    }
  };

  const handleVerify = (targetString: string) => {
    if (!targetString.trim()) return;
    const analyzed = analyzeTarget(targetString.trim());
    setScanResult(analyzed);
    setIsResultModalOpen(true);

    // Save to audit history
    setScanHistory((prev) => {
      const updated = [analyzed, ...prev.filter((item) => item.target !== analyzed.target)].slice(0, 20);
      try {
        sessionStorage.setItem('phishlens_audit_history', JSON.stringify(updated));
      } catch {
        // safe
      }
      return updated;
    });
  };

  const handleInputSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleVerify(urlInput);
  };

  const handleScanSuccess = (data: string) => {
    setUrlInput(data);
    handleVerify(data);
  };

  const handleClearHistory = () => {
    setScanHistory([]);
    sessionStorage.removeItem('phishlens_audit_history');
  };

  const handleDownloadZip = async () => {
    setIsZipping(true);
    try {
      await exportSoftwareZip(scanResult);
    } catch (err) {
      console.error('ZIP export failed:', err);
    } finally {
      setIsZipping(false);
    }
  };

  // Demo scenarios
  const demoScenarios = [
    {
      label: t.demoScenarios.fakeKyc,
      dotColor: 'bg-rose-500',
      value: 'https://secure-hdfc-kyc.com/update-pan',
      tab: 'kyc' as NavTab,
    },
    {
      label: t.demoScenarios.fakeUpi,
      dotColor: 'bg-rose-500',
      value: 'refundhelp@unauthorizedfakebank',
      tab: 'upi' as NavTab,
    },
    {
      label: t.demoScenarios.misspelledGoogle,
      dotColor: 'bg-rose-500',
      value: 'https://g\u043E\u043Egle.com/accounts', // Cyrillic homoglyph (U+043E)
      tab: 'link' as NavTab,
    },
    {
      label: t.demoScenarios.deceptivePaypal,
      dotColor: 'bg-amber-500',
      value: 'https://paypa1.com/verify-account',
      tab: 'link' as NavTab,
    },
    {
      label: t.demoScenarios.collectScamUpi,
      dotColor: 'bg-amber-500',
      value: 'upi://pay?pa=lotterywinner@okhdfcbank&pn=Cashback%20Reward&am=4999&cu=INR&tn=Receive%20Cashback%20Bonus',
      tab: 'upi' as NavTab,
    },
    {
      label: t.demoScenarios.officialSbi,
      dotColor: 'bg-emerald-500',
      value: 'https://sbi.co.in',
      tab: 'link' as NavTab,
    },
    {
      label: t.demoScenarios.verifiedSwiggy,
      dotColor: 'bg-emerald-500',
      value: 'swiggy@icici',
      tab: 'upi' as NavTab,
    },
  ];

  const handleSelectScenario = (scenario: typeof demoScenarios[0]) => {
    setActiveTab(scenario.tab);
    setUrlInput(scenario.value);
    handleVerify(scenario.value);
  };

  // Dynamic tab configurations
  const getTabConfig = () => {
    switch (activeTab) {
      case 'link':
        return {
          title: t.cards.linkTitle,
          badge: t.cards.linkBadge,
          description: t.cards.linkDesc,
          placeholder: t.cards.linkPlaceholder,
          inputLabel: t.cards.inputLabel,
        };
      case 'upi':
        return {
          title: t.cards.upiTitle,
          badge: t.cards.upiBadge,
          description: t.cards.upiDesc,
          placeholder: t.cards.upiPlaceholder,
          inputLabel: t.cards.inputLabel,
        };
      case 'kyc':
        return {
          title: t.cards.kycTitle,
          badge: t.cards.kycBadge,
          description: t.cards.kycDesc,
          placeholder: t.cards.kycPlaceholder,
          inputLabel: t.cards.inputLabel,
        };
      case 'scan-qr':
        return {
          title: t.cards.qrTitle,
          badge: t.cards.qrBadge,
          description: t.cards.qrDesc,
          placeholder: t.cards.qrPlaceholder,
          inputLabel: t.cards.inputLabel,
        };
      case 'upload':
        return {
          title: t.cards.uploadTitle,
          badge: t.cards.uploadBadge,
          description: t.cards.uploadDesc,
          placeholder: t.cards.uploadPlaceholder,
          inputLabel: t.cards.inputLabel,
        };
    }
  };

  const tabConfig = getTabConfig();

  return (
    <div className="min-h-screen bg-[#fcf9fa] text-slate-800 flex flex-col font-sans selection:bg-rose-500/20 selection:text-rose-700">
      {/* 1. Responsive Top Navigation Bar */}
      <header className="sticky top-0 z-40 w-full bg-white/95 backdrop-blur-xs border-b border-slate-200/80 shadow-2xs">
        <div className="max-w-[1400px] mx-auto px-3 sm:px-6 h-16 sm:h-18 flex items-center justify-between gap-2 sm:gap-4">
          {/* Left Brand Lockup with Custom Magnifying Lens + QR Logo */}
          <div className="flex items-center gap-2 sm:gap-3">
            <button
              onClick={() => setIsSidebarOpen(true)}
              className="p-2 rounded-xl bg-white border border-rose-200 hover:bg-rose-50 text-rose-600 transition-colors shadow-2xs cursor-pointer"
              aria-label="Open History & Guidelines"
              title="Open History & Guidelines"
            >
              <Menu className="w-5 h-5" />
            </button>

            <a href="/" className="flex items-center gap-2.5 group">
              <PhishLensLogo size={36} className="transition-transform group-hover:scale-105" />
              <div className="flex flex-col">
                <span className="text-base sm:text-lg font-extrabold tracking-tight text-slate-900 leading-tight">
                  PhishLens
                </span>
                <span className="text-[10px] sm:text-[11px] font-semibold text-[#e11d48] leading-tight">
                  Fraud Protection &amp; Threat Verification
                </span>
              </div>
            </a>
          </div>

          {/* Center Navigation Bar (Capsule Segmented Bar for desktop) */}
          <nav className="hidden lg:flex items-center gap-1 p-1 bg-white border border-slate-300/80 rounded-full shadow-2xs">
            <button
              onClick={() => setActiveTab('link')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-full transition-all cursor-pointer ${
                activeTab === 'link'
                  ? 'bg-[#e11d48] text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>{t.tabs.link}</span>
            </button>

            <button
              onClick={() => setActiveTab('upi')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-full transition-all cursor-pointer ${
                activeTab === 'upi'
                  ? 'bg-[#e11d48] text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <CreditCard className="w-3.5 h-3.5" />
              <span>{t.tabs.upi}</span>
            </button>

            <button
              onClick={() => setActiveTab('kyc')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-full transition-all cursor-pointer ${
                activeTab === 'kyc'
                  ? 'bg-[#e11d48] text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>{t.tabs.kyc}</span>
            </button>

            <button
              onClick={() => setActiveTab('scan-qr')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-full transition-all cursor-pointer ${
                activeTab === 'scan-qr'
                  ? 'bg-[#e11d48] text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Camera className="w-3.5 h-3.5" />
              <span>{t.tabs.scanQr}</span>
            </button>

            <button
              onClick={() => setActiveTab('upload')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-full transition-all cursor-pointer ${
                activeTab === 'upload'
                  ? 'bg-[#e11d48] text-white shadow-xs'
                  : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{t.tabs.upload}</span>
            </button>
          </nav>

          {/* Right Controls */}
          <div className="flex items-center gap-2 sm:gap-2.5">
            {/* Language Selector Dropdown (18 Languages) */}
            <div className="relative">
              <button
                onClick={() => setShowLanguageDropdown(!showLanguageDropdown)}
                className="inline-flex items-center gap-1 sm:gap-1.5 px-2.5 sm:px-3 py-1.5 text-xs font-semibold text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-300 rounded-full transition-all shadow-2xs cursor-pointer"
                title="Select Multi-Lingual Interface Language"
              >
                <Languages className="w-3.5 h-3.5 text-rose-500" />
                <span className="max-w-[70px] sm:max-w-none truncate">{LANGUAGE_OPTIONS.find((l) => l.code === currentLanguage)?.native || 'English'}</span>
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>

              {showLanguageDropdown && (
                <div className="absolute right-0 mt-1.5 w-52 max-h-80 overflow-y-auto bg-white border border-slate-200 rounded-2xl shadow-xl py-1 z-50 text-xs">
                  <div className="px-3.5 py-1.5 text-[10px] font-bold uppercase text-slate-400 border-b border-slate-100">
                    Select Language ({LANGUAGE_OPTIONS.length})
                  </div>
                  {LANGUAGE_OPTIONS.map((lang) => (
                    <button
                      key={lang.code}
                      onClick={() => handleLanguageChange(lang.code)}
                      className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors cursor-pointer ${
                        currentLanguage === lang.code
                          ? 'bg-rose-50 text-[#e11d48] font-bold'
                          : 'text-slate-700 hover:bg-slate-50 hover:text-slate-900'
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <span>{lang.flag}</span>
                        <span>{lang.native}</span>
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">{lang.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* ZIP Export Button */}
            <button
              onClick={handleDownloadZip}
              disabled={isZipping}
              className="inline-flex items-center gap-1 px-3 sm:px-3.5 py-1.5 text-xs font-bold text-white bg-[#e11d48] hover:bg-[#be123c] active:bg-[#9f1239] rounded-full shadow-xs transition-colors cursor-pointer shrink-0"
              title="Download Full Software ZIP (Frontend + Threat Engine)"
            >
              <Archive className="w-3.5 h-3.5" />
              <span>{isZipping ? 'Zipping...' : t.actions.exportZip}</span>
            </button>
          </div>
        </div>

        {/* Mobile Navigation Tabs (Horizontally scrollable) */}
        <div className="lg:hidden flex items-center overflow-x-auto px-3 py-2 border-t border-slate-100 gap-1.5 scrollbar-none touch-pan-x">
          {[
            { id: 'link', label: t.tabs.link, icon: Globe },
            { id: 'upi', label: t.tabs.upi, icon: CreditCard },
            { id: 'kyc', label: t.tabs.kyc, icon: FileText },
            { id: 'scan-qr', label: t.tabs.scanQr, icon: Camera },
            { id: 'upload', label: t.tabs.upload, icon: Upload },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as NavTab)}
                className={`inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-full whitespace-nowrap transition-colors shrink-0 ${
                  activeTab === tab.id
                    ? 'bg-[#e11d48] text-white font-semibold shadow-xs'
                    : 'bg-white text-slate-700 border border-slate-200'
                }`}
              >
                <Icon className="w-3 h-3" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </header>

      {/* 2. Main Content Area */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-3 sm:px-6 py-6 sm:py-8 space-y-6">
        {/* Main Central Card */}
        <div className="bg-white border-2 border-slate-900 rounded-[28px] p-5 sm:p-8 shadow-sm relative transition-all">
          {/* Consistent Unified Header for ALL tabs */}
          <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-[#e11d48]" />
              <h2 className="bg-rose-100/70 text-[#be123c] font-black text-xl sm:text-2xl px-2.5 py-0.5 rounded-lg inline-block tracking-tight">
                {tabConfig.title}
              </h2>
            </div>
            <span className="bg-rose-50 border border-rose-200 text-[#e11d48] text-xs font-bold px-3 py-0.5 rounded-full uppercase tracking-wider">
              {tabConfig.badge}
            </span>
          </div>

          {/* Subtitle */}
          <p className="text-slate-600 text-xs sm:text-sm mb-5">
            {tabConfig.description}
          </p>

          {/* Active Tab Interactive Area */}
          {activeTab === 'scan-qr' ? (
            <div className="mb-5">
              <QrCameraScanner
                onScanSuccess={handleScanSuccess}
                onSwitchToUpload={() => setActiveTab('upload')}
              />
            </div>
          ) : activeTab === 'upload' ? (
            <div className="mb-5">
              <ImageQrUploader onScanSuccess={handleScanSuccess} />
            </div>
          ) : (
            /* Dynamic Target Input Form */
            <form onSubmit={handleInputSubmit} className="mb-5">
              <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                {tabConfig.inputLabel}
              </label>

              <div className="rounded-2xl border-2 border-slate-300 bg-white p-2 pl-3 sm:pl-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 shadow-2xs focus-within:border-[#e11d48] focus-within:ring-3 focus-within:ring-rose-100 transition-all">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder={tabConfig.placeholder}
                  className="font-mono text-xs sm:text-sm text-slate-800 placeholder:text-slate-400 bg-transparent flex-1 outline-none py-1.5"
                />

                <div className="flex items-center gap-1.5 shrink-0">
                  {urlInput && (
                    <button
                      type="button"
                      onClick={() => setUrlInput('')}
                      className="p-2 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
                      title={t.actions.clear}
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}

                  <button
                    type="submit"
                    className="w-full sm:w-auto bg-[#e11d48] hover:bg-[#be123c] active:bg-[#9f1239] text-white font-bold text-xs sm:text-sm px-5 sm:px-6 py-2.5 rounded-xl flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer whitespace-nowrap"
                  >
                    <Shield className="w-4 h-4" />
                    <span>{t.actions.verifyTarget}</span>
                  </button>
                </div>
              </div>
            </form>
          )}

          {/* Interactive Demo Scenarios & Quick Presets */}
          <div className="border-t border-slate-100 pt-4">
            <span className="text-rose-600 text-[11px] font-bold tracking-wider uppercase mb-2.5 block">
              {t.demoHeader}
            </span>

            <div className="flex flex-wrap items-center gap-2">
              {demoScenarios.map((scenario, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSelectScenario(scenario)}
                  className="border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 rounded-full px-3 py-1.5 text-xs font-medium text-slate-800 flex items-center gap-2 transition-all shadow-2xs cursor-pointer group"
                >
                  <span className={`w-2 h-2 rounded-full ${scenario.dotColor} shrink-0`} />
                  <span className="group-hover:text-rose-600 transition-colors">
                    {scenario.label}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </main>

      {/* 3. Result Popup Modal */}
      <ResultModal
        result={scanResult}
        isOpen={isResultModalOpen}
        onClose={() => setIsResultModalOpen(false)}
        t={t}
      />

      {/* 4. Left History & Guidelines Sidebar */}
      <HistoryGuidelinesSidebar
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        history={scanHistory}
        onSelectHistory={(item) => {
          setScanResult(item);
          setIsResultModalOpen(true);
        }}
        onClearHistory={handleClearHistory}
        t={t}
      />

      {/* 5. Responsive Clean Footer */}
      <footer className="mt-auto border-t border-slate-200 bg-white py-5 text-xs text-slate-500">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-center sm:text-left">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-800">PhishLens</span>
            <span>&middot;</span>
            <span>Phishing &amp; Scam Verification Engine</span>
          </div>

          <div className="flex items-center gap-4 text-slate-500">
            <span>Client-Side Local Scan</span>
            <span>&middot;</span>
            <span className="text-emerald-700 font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> 60+ NPCI Handles Active
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
