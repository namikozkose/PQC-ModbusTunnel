package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// =====================================================================
// PROJE: PQC-ModbusTunnel (Kuantum-Dirençli SCADA Ağ Tüneli)
// HEDEF: Kyber-768 (KEM) ile AES-256-GCM (AEAD) Hibrit Tünel Mimarisi
// =====================================================================

func main() {
	fmt.Println("[*] Kuantum-Dirençli SCADA Tüneli Başlatılıyor...")
	scheme := kyber768.Scheme()

	// =====================================================================
	// FAZ 1: KYBER İLE KUANTUM-DİRENÇLİ EL SIKIŞMA (HANDSHAKE)
	// =====================================================================
	fmt.Println("\n--- [FAZ 1] KUANTUM EL SIKIŞMA (KYBER-768) ---")

	// 1. Merkez SOC (Sunucu) Kuantum Anahtarlarını Üretir
	pubKey, privKey, _ := scheme.GenerateKeyPair()

	// 2. Tesis Modbus Ajanı (İstemci) Kapsülü ve Ortak Sırrı Üretir
	ciphertext, clientSecret, _ := scheme.Encapsulate(pubKey)

	// 3. Merkez SOC (Sunucu) Gelen Kapsülü Çözer
	serverSecret, _ := scheme.Decapsulate(privKey, ciphertext)

	fmt.Printf("[+] İstemci AES Anahtarı : %x...\n", clientSecret[:8])
	fmt.Printf("[+] Sunucu AES Anahtarı  : %x...\n", serverSecret[:8])
	fmt.Println("[🛡️] El Sıkışma Başarılı! Her iki taraf da aynı AES-256 anahtarına sahip.")

	// =====================================================================
	// FAZ 2: AES-256-GCM İLE GÜVENLİ VERİ TÜNELİ (DATA TUNNEL)
	// =====================================================================
	fmt.Println("\n--- [FAZ 2] AES-256-GCM MODBUS TÜNELİ ---")

	// Hatırlarsan bu, Donanım NIDS (VHDL) projemizdeki o meşhur sabotaj paketi:
	// 00 01 (Trans ID) 00 00 (Proto) 00 06 (Len) 01 (Unit) 05 (Write Coil) 00 00 FF 00
	modbusPayload := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x00, 0xFF, 0x00}

	fmt.Printf("[!] Orijinal Modbus Paketi (Plaintext): %x\n", modbusPayload)

	// --- A) İSTEMCİ (TESİS) PAKETİ ŞİFRELEYİP GÖNDERİYOR ---
	encryptedPacket := encryptAES_GCM(clientSecret, modbusPayload)
	fmt.Printf("[>] İnternetten Akan Şifreli Veri (Ciphertext): %x\n", encryptedPacket)
	fmt.Println("    (Araya girenler sadece bu anlamsız byte yığınını görecek!)")

	// --- B) SUNUCU (MERKEZ SOC) PAKETİ ALIP ÇÖZÜYOR ---
	decryptedPacket := decryptAES_GCM(serverSecret, encryptedPacket)
	fmt.Printf("[<] Sunucuda Çözülen Modbus Paketi    : %x\n", decryptedPacket)

	// Doğrulama
	if string(modbusPayload) == string(decryptedPacket) {
		fmt.Println("\n[🎯] OPERASYON BAŞARILI!")
		fmt.Println("     Modbus paketi kuantum dirençli bir tünelden (Kyber + AES)")
		fmt.Println("     milisekiyeler içinde güvenle aktarıldı.")
	}
}

// =====================================================================
// ŞİFRELEME MOTORLARI (Kriptografik Araçlar)
// =====================================================================

// encryptAES_GCM: Veriyi AES-256-GCM kullanarak şifreler
func encryptAES_GCM(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("AES Blok hatası: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("GCM hatası: %v", err)
	}

	// GCM için tek kullanımlık rastgele Nonce (Number Used Once) üretimi
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("Nonce üretilemedi: %v", err)
	}

	// Nonce'u şifreli verinin en başına ekliyoruz ki karşı taraf çözerken kullanabilsin
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

// decryptAES_GCM: AES-256-GCM ile şifrelenmiş veriyi çözer
func decryptAES_GCM(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("AES Blok hatası: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("GCM hatası: %v", err)
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatalf("Şifreli metin çok kısa!")
	}

	// En baştaki Nonce'u ayırıyoruz, kalan kısım asıl şifreli veri
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		log.Fatalf("Şifre çözme hatası (Veri bozuk veya değiştirilmiş!): %v", err)
	}

	return plaintext
}
