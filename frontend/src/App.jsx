import { useState, useEffect } from 'react';
import InvestigationResult from './components/InvestigationResult';

function App() {
  const [apiStatus, setApiStatus] = useState('Checking...');
  const [target, setTarget] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    fetch('/api/health')
      .then((res) => {
        if (res.ok) {
          setApiStatus('API Online');
        } else {
          setApiStatus('API Unavailable');
        }
      })
      .catch(() => {
        setApiStatus('API Unavailable');
      });
  }, []);

  const handleInvestigate = async (e) => {
    e.preventDefault();
    const trimmedTarget = target.trim();
    if (!trimmedTarget) return;

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target: trimmedTarget }),
      });

      if (!response.ok) {
        if (response.status === 422) {
          const errorData = await response.json();
          setError(errorData.detail || "Invalid target format.");
        } else {
          setError("Unable to complete the investigation. Please try again.");
        }
        setIsLoading(false);
        return;
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError("Unable to complete the investigation. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col font-sans text-gray-900">
      <header className="bg-white shadow-sm border-b border-gray-200 py-4 px-6 flex justify-between items-center">
        <h1 className="text-xl font-bold tracking-tight text-blue-900">OpenPivot</h1>
        <div className="flex items-center space-x-2 text-sm">
          <span className={`h-2.5 w-2.5 rounded-full ${apiStatus === 'API Online' ? 'bg-green-500' : apiStatus === 'Checking...' ? 'bg-gray-400' : 'bg-red-500'}`}></span>
          <span className="text-gray-600 font-medium">{apiStatus}</span>
        </div>
      </header>

      <main className="flex-grow flex flex-col items-center py-12 px-4 w-full">
        <div className="max-w-4xl w-full text-center space-y-8">
          <div>
            <h2 className="text-4xl font-extrabold text-gray-900 sm:text-5xl tracking-tight mb-4">
              Infrastructure Intelligence
            </h2>
            <p className="text-lg text-gray-600 max-w-xl mx-auto">
              Public infrastructure intelligence for domains and IP addresses.
            </p>
          </div>

          <div className="bg-white p-6 md:p-8 rounded-xl shadow-sm border border-gray-100 max-w-2xl mx-auto">
            <form className="flex flex-col sm:flex-row gap-3" onSubmit={handleInvestigate}>
              <input
                type="text"
                placeholder="example.com or 8.8.8.8"
                className="flex-grow px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-shadow disabled:bg-gray-100 disabled:text-gray-500"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isLoading}
                aria-label="Investigation target"
              />
              <button
                type="submit"
                className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:bg-blue-400 disabled:cursor-not-allowed"
                disabled={isLoading || !target.trim()}
              >
                {isLoading ? 'Investigating...' : 'Investigate'}
              </button>
            </form>
            {error && (
              <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm border border-red-100 text-left">
                {error}
              </div>
            )}
          </div>
          <InvestigationResult result={result} />

          <p className="text-sm text-gray-500 mt-8 pb-8">
            OpenPivot exclusively utilizes publicly available technical information.
          </p>
        </div>
      </main>
    </div>
  );
}

export default App;
