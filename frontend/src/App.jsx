import { useState, useEffect } from 'react';

function App() {
  const [apiStatus, setApiStatus] = useState('Checking...');

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

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col font-sans text-gray-900">
      <header className="bg-white shadow-sm border-b border-gray-200 py-4 px-6 flex justify-between items-center">
        <h1 className="text-xl font-bold tracking-tight text-blue-900">OpenPivot</h1>
        <div className="flex items-center space-x-2 text-sm">
          <span className={`h-2.5 w-2.5 rounded-full ${apiStatus === 'API Online' ? 'bg-green-500' : apiStatus === 'Checking...' ? 'bg-gray-400' : 'bg-red-500'}`}></span>
          <span className="text-gray-600 font-medium">{apiStatus}</span>
        </div>
      </header>

      <main className="flex-grow flex flex-col items-center justify-center px-4 py-12">
        <div className="max-w-2xl w-full text-center space-y-8">
          <div>
            <h2 className="text-4xl font-extrabold text-gray-900 sm:text-5xl tracking-tight mb-4">
              Infrastructure Intelligence
            </h2>
            <p className="text-lg text-gray-600 max-w-xl mx-auto">
              Public infrastructure intelligence for domains and IP addresses.
            </p>
          </div>

          <div className="bg-white p-6 md:p-8 rounded-xl shadow-sm border border-gray-100">
            <form className="flex flex-col sm:flex-row gap-3" onSubmit={(e) => e.preventDefault()}>
              <input
                type="text"
                placeholder="example.com or 8.8.8.8"
                className="flex-grow px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-shadow"
              />
              <button
                type="submit"
                className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                Investigate
              </button>
            </form>
          </div>

          <p className="text-sm text-gray-500">
            OpenPivot exclusively utilizes publicly available technical information.
          </p>
        </div>
      </main>
    </div>
  );
}

export default App;
