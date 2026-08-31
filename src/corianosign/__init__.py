"""CorianoSign - verifica firme digitali e apertura file .p7m (CAdES).

App cross-platform (macOS Apple Silicon / Windows) per:
  * aprire buste CMS/PKCS#7 (.p7m, firma CAdES-BES italiana);
  * verificare la validita' crittografica della/e firma/e;
  * validare la catena di certificazione verso le Trusted List europee/AgID
    con controllo di revoca (CRL/OCSP);
  * estrarre il documento originale contenuto nella busta.
"""

__version__ = "0.2.5"
__app_name__ = "CorianoSign"
