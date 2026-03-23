import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./styles/global.css";
import { Layout } from "./components/Layout";
import { Home } from "./pages/Home";
import { DocPage } from "./pages/DocPage";
import { Verify } from "./pages/Verify";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="/verify" element={<Verify />} />
          <Route path="/docs/:slug" element={<DocPage />} />
          <Route path="/docs" element={<DocPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
