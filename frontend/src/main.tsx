import '@fontsource-variable/atkinson-hyperlegible-next'
import '@fontsource-variable/atkinson-hyperlegible-mono'
import './styles/app.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AegisProvider } from './state/AegisProvider'
import { FeedbackProvider } from './state/feedback'
import { Shell } from './components/Shell'
import { Overview } from './pages/Overview'
import { Incidents } from './pages/Incidents'
import { Review } from './pages/Review'
import { Quarantine } from './pages/Quarantine'
import { Audit } from './pages/Audit'
import { Simulate } from './pages/Simulate'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <HashRouter>
      <AegisProvider>
        <FeedbackProvider>
          <Routes>
            <Route element={<Shell />}>
              <Route index element={<Overview />} />
              <Route path="incidents/:id?" element={<Incidents />} />
              <Route path="review/:id?" element={<Review />} />
              <Route path="quarantine/:pod?" element={<Quarantine />} />
              <Route path="audit" element={<Audit />} />
              <Route path="simulate" element={<Simulate />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </FeedbackProvider>
      </AegisProvider>
    </HashRouter>
  </StrictMode>,
)
