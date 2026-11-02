/* Einstellungen für die OneDrive-Verbindung.
   Tragen Sie hier die «Anwendungs-ID (Client-ID)» Ihrer Microsoft-App-Registrierung ein
   (siehe ANLEITUNG.md, Schritt 3). Die Client-ID ist kein Geheimnis: Sie identifiziert
   nur die App. Ein Client-Geheimnis oder Passwort gehört NICHT hierher.

   Alternativ können Sie die Client-ID auch direkt in der App unter
   «Cloud und Synchronisierung» eintragen; dann gilt sie nur für dieses Gerät. */
window.APP_CONFIG = {
  clientId: '',
  // 'consumers' = nur private Microsoft-Konten (outlook.com, hotmail.com, live.com …)
  // 'common'    = private Konten und Schul-/Geschäftskonten
  authority: 'consumers',
};
