# ============================================
# TERMUX SECURITY HARDENING ============================================

# 1. HOME VERZEICHNIS
chmod 700 ~

# 2. SSH VERZEICHNIS
if [ -d ~/.ssh ]; then
    chmod 700 ~/.ssh
    
    # Konfigurationsdateien
    [ -f ~/.ssh/authorized_keys ] && chmod 600 ~/.ssh/authorized_keys
    [ -f ~/.ssh/config ] && chmod 600 ~/.ssh/config
    [ -f ~/.ssh/known_hosts ] && chmod 644 ~/.ssh/known_hosts
    
    # Standard SSH Keys
    [ -f ~/.ssh/id_rsa ] && chmod 600 ~/.ssh/id_rsa
    [ -f ~/.ssh/id_ed25519 ] && chmod 600 ~/.ssh/id_ed25519
    [ -f ~/.ssh/id_ecdsa ] && chmod 600 ~/.ssh/id_ecdsa
    [ -f ~/.ssh/id_dsa ] && chmod 600 ~/.ssh/id_dsa
    
    # Public Keys
    [ -f ~/.ssh/id_rsa.pub ] && chmod 644 ~/.ssh/id_rsa.pub
    [ -f ~/.ssh/id_ed25519.pub ] && chmod 644 ~/.ssh/id_ed25519.pub
    [ -f ~/.ssh/id_ecdsa.pub ] && chmod 644 ~/.ssh/id_ecdsa.pub
    [ -f ~/.ssh/id_dsa.pub ] && chmod 644 ~/.ssh/id_dsa.pub
fi

# 3. SHELL KONFIGURATION
[ -f ~/.bashrc ] && chmod 644 ~/.bashrc
[ -f ~/.bash_profile ] && chmod 644 ~/.bash_profile
[ -f ~/.profile ] && chmod 644 ~/.profile
[ -f ~/.bash_history ] && chmod 600 ~/.bash_history

# 4. TERMUX KONFIGURATION
[ -d ~/.termux ] && chmod 700 ~/.termux

# 5. VERSCHLÜSSELUNG & KEYS
[ -d ~/.gnupg ] && chmod 700 ~/.gnupg

# 6. CLOUD CREDENTIALS
[ -d ~/.aws ] && chmod 700 ~/.aws

# 7. USER BINARIES
if [ -d ~/.local/bin ]; then
    for file in ~/.local/bin/*; do
        # Prüfe, ob es eine reguläre Datei ist (kein Verzeichnis)
        if [ -f "$file" ]; then
            chmod 755 "$file"
        fi
    done
fi

echo "✅ Alle Kern-Berechtigungen gesetzt!"