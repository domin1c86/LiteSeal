import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import AppLock from "./components/AppLock";
import BackupArchive from "./components/BackupArchive";
import "./theme.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {window.location.hash.startsWith("#archive=") ? <BackupArchive id={decodeURIComponent(window.location.hash.slice(9))} /> : <AppLock><App /></AppLock>}
  </React.StrictMode>
);
