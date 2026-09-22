import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import AppLock from "./components/AppLock";
import "./theme.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AppLock><App /></AppLock>
  </React.StrictMode>
);
