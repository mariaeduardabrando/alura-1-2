// ============================================================
// LABORATÓRIO DE CRIPTOGRAFIA E SEGURANÇA
// Atende aos critérios:
// - Criptografia por substituição (Cifra de César)
// - Funções hash para senhas (SHA-256 + salt)
// - Simulação de força bruta
// - Estruturas condicionais e de repetição
// - Boas práticas de segurança
// ============================================================

// ============================================================
// 1. CRIPTOGRAFIA POR SUBSTITUIÇÃO
// ============================================================
function cesar(texto, deslocamento) {
    // Validações condicionais
    if (typeof texto !== "string") return "";
    if (!Number.isInteger(deslocamento)) return texto;

    let resultado = "";

    // Estrutura de repetição: percorre cada caractere
    for (let i = 0; i < texto.length; i++) {
        const codigo = texto.charCodeAt(i);

        if (codigo >= 65 && codigo <= 90) {
            // Letra maiúscula (A-Z)
            resultado += String.fromCharCode(
                ((codigo - 65 + deslocamento + 2600) % 26) + 65
            );
        } else if (codigo >= 97 && codigo <= 122) {
            // Letra minúscula (a-z)
            resultado += String.fromCharCode(
                ((codigo - 97 + deslocamento + 2600) % 26) + 97
            );
        } else {
            resultado += texto[i]; // outros caracteres inalterados
        }
    }
    return resultado;
}

function cifrar(texto, d) { return cesar(texto, d); }
function decifrar(texto, d) { return cesar(texto, -d); }

function quebrarCesar(texto) {
    const tentativas = [];
    for (let d = 1; d <= 25; d++) {
        tentativas.push(`[${d}] ${cesar(texto, -d)}`);
    }
    return tentativas.join("\n");
}

// ============================================================
// 2. FUNÇÕES HASH (SHA-256 + SALT)
// ============================================================
async function sha256(mensagem) {
    const dados = new TextEncoder().encode(mensagem);
    const buffer = await crypto.subtle.digest("SHA-256", dados);
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function gerarSalt(tamanho = 8) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(tamanho));
    return Array.from(saltBytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

async function hashComSalt(senha) {
    if (typeof senha !== "string" || senha.length === 0) {
        throw new Error("Senha inválida");
    }
    const salt = gerarSalt();
    const hash = await sha256(salt + senha);
    return { salt, hash };
}

async function verificarSenha(senha, salt, hashArmazenado) {
    if (!senha || !salt || !hashArmazenado) return false;
    const hashCalculado = await sha256(salt + senha);
    return hashCalculado === hashArmazenado;
}

// ============================================================
// 3. SIMULAÇÃO DE FORÇA BRUTA
// ============================================================
async function simularAtaque(alvo, tamanhoAlfabeto = 26, onProgresso = null) {
    if (typeof alvo !== "string" || alvo.length === 0) {
        throw new Error("Senha alvo inválida");
    }

    let alfabeto = "abcdefghijklmnopqrstuvwxyz";
    if (tamanhoAlfabeto === 36) alfabeto += "0123456789";
    if (tamanhoAlfabeto === 52) alfabeto += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const LIMITE = 5_000_000;
    const TAMANHO_MAX = Math.min(alvo.length, 6);

    const inicio = performance.now();
    let tentativas = 0;
    let encontrada = false;

    // Loop externo: tamanho da senha
    for (let len = 1; len <= TAMANHO_MAX && !encontrada; len++) {
        const indices = new Array(len).fill(0);

        while (true) {
            // Monta candidato
            let candidato = "";
            for (let i = 0; i < len; i++) {
                candidato += alfabeto[indices[i]];
            }
            tentativas++;

            // Condicional: encontrou a senha?
            if (candidato === alvo) {
                encontrada = true;
                break;
            }

            // Callback de progresso a cada 100 mil tentativas
            if (onProgresso && tentativas % 100_000 === 0) {
                onProgresso(tentativas);
                await new Promise(r => setTimeout(r, 0));
            }

            // Incrementa índices (contador posicional)
            let pos = len - 1;
            while (pos >= 0) {
                indices[pos]++;
                if (indices[pos] < alfabeto.length) break;
                indices[pos] = 0;
                pos--;
            }
            if (pos < 0) break; // esgotou combinações

            // Limite de segurança
            if (tentativas >= LIMITE) {
                return {
                    encontrada: false,
                    senha: null,
                    tentativas,
                    tempoMs: performance.now() - inicio,
                    limite: true,
                };
            }
        }
    }

    return {
        encontrada,
        senha: encontrada ? alvo : null,
        tentativas,
        tempoMs: performance.now() - inicio,
        limite: false,
    };
}

// ============================================================
// 4. BOAS PRÁTICAS DE SEGURANÇA
// ============================================================
const boasPraticas = [
    "Use senhas longas (mínimo 12 caracteres) combinando maiúsculas, minúsculas, números e símbolos.",
    "Nunca reutilize a mesma senha entre serviços diferentes.",
    "Ative autenticação em dois fatores (2FA) sempre que possível.",
    "Armazene senhas apenas como hash + salt (bcrypt, Argon2, scrypt) — nunca em texto puro.",
    "Utilize HTTPS para proteger dados em trânsito.",
    "Mantenha sistemas e bibliotecas sempre atualizados.",
    "Aplique o princípio do menor privilégio: conceda apenas permissões necessárias.",
    "Limite tentativas de login para dificultar ataques de força bruta.",
    "Não utilize algoritmos obsoletos como MD5 ou SHA-1 para senhas.",
    "Faça backup regular dos dados e teste a restauração.",
];

// ============================================================
// CONEXÃO COM O DOM
// ============================================================
document.addEventListener("DOMContentLoaded", () => {

    // ---------- 1. CRIPTOGRAFIA ----------
    const textoCifra = document.getElementById("textoCifra");
    const deslocamento = document.getElementById("deslocamento");
    const resultadoCifra = document.getElementById("resultadoCifra");

    document.getElementById("btnCifrar").addEventListener("click", () => {
        if (!textoCifra.value.trim()) {
            resultadoCifra.innerHTML = "<span class='alerta'>Digite uma mensagem.</span>";
            return;
        }
        resultadoCifra.textContent = cifrar(textoCifra.value, parseInt(deslocamento.value));
    });

    document.getElementById("btnDecifrar").addEventListener("click", () => {
        if (!textoCifra.value.trim()) {
            resultadoCifra.innerHTML = "<span class='alerta'>Digite uma mensagem.</span>";
            return;
        }
        resultadoCifra.textContent = decifrar(textoCifra.value, parseInt(deslocamento.value));
    });

    document.getElementById("btnQuebrar").addEventListener("click", () => {
        if (!textoCifra.value.trim()) {
            resultadoCifra.innerHTML = "<span class='alerta'>Digite uma mensagem.</span>";
            return;
        }
        resultadoCifra.textContent =
            "Tentativas de decifração (1 a 25):\n\n" + quebrarCesar(textoCifra.value);
    });

    document.getElementById("btnLimparCifra").addEventListener("click", () => {
        textoCifra.value = "";
        resultadoCifra.textContent = "Resultado aparecerá aqui...";
    });

    // ---------- 2. HASH ----------
    const senhaHash = document.getElementById("senhaHash");
    const resultadoHash = document.getElementById("resultadoHash");
    let hashAtual = null;

    document.getElementById("btnGerarHash").addEventListener("click", async () => {
        const senha = senhaHash.value;
        if (!senha) {
            resultadoHash.innerHTML = "<span class='alerta'>Digite uma senha primeiro.</span>";
            return;
        }
        try {
            hashAtual = await hashComSalt(senha);
            resultadoHash.innerHTML = `
                <strong>Salt:</strong> ${hashAtual.salt}<br>
                <strong>Hash (SHA-256):</strong> ${hashAtual.hash}<br>
                <span class="sucesso">✓ Hash gerado com salt aplicado.</span>
            `;
        } catch (e) {
            resultadoHash.innerHTML = `<span class="alerta">Erro: ${e.message}</span>`;
        }
    });

    document.getElementById("btnCompararHash").addEventListener("click", async () => {
        if (!hashAtual) {
            resultadoHash.innerHTML = "<span class='alerta'>Gere um hash primeiro.</span>";
            return;
        }
        const senha = senhaHash.value;
        const valido = await verificarSenha(senha, hashAtual.salt, hashAtual.hash);
        if (valido) {
            resultadoHash.innerHTML +=
                `<br><span class="sucesso">✓ Senha correta! Hash coincide.</span>`;
        } else {
            resultadoHash.innerHTML +=
                `<br><span class="alerta">✗ Senha incorreta!</span>`;
        }
    });

    // ---------- 3. FORÇA BRUTA ----------
    const senhaAlvo = document.getElementById("senhaAlvo");
    const alfabetoForca = document.getElementById("alfabetoForca");
    const resultadoForca = document.getElementById("resultadoForca");
    const infoForca = document.getElementById("infoForca");
    const btnForcaBruta = document.getElementById("btnForcaBruta");

    btnForcaBruta.addEventListener("click", async () => {
        const alvo = senhaAlvo.value.trim();
        const tipo = parseInt(alfabetoForca.value);

        if (!alvo) {
            resultadoForca.innerHTML = "<span class='alerta'>Defina uma senha alvo.</span>";
            return;
        }

        btnForcaBruta.disabled = true;
        resultadoForca.innerHTML = "🔄 Iniciando ataque...";
        infoForca.textContent = "";

        try {
            const r = await simularAtaque(alvo, tipo, (tentativas) => {
                resultadoForca.textContent =
                    `🔄 Tentando... ${tentativas.toLocaleString("pt-BR")} combinações`;
            });

            if (r.encontrada) {
                resultadoForca.innerHTML = `
                    <span class="sucesso">✓ Senha encontrada: "${r.senha}"</span><br>
                    <strong>Tentativas:</strong> ${r.tentativas.toLocaleString("pt-BR")}<br>
                    <strong>Tempo:</strong> ${r.tempoMs.toFixed(2)} ms
                `;
            } else if (r.limite) {
                resultadoForca.innerHTML = `
                    <span class="alerta">⚠ Limite de 5 milhões de tentativas atingido.</span><br>
                    Tentativas: ${r.tentativas.toLocaleString("pt-BR")} |
                    Tempo: ${r.tempoMs.toFixed(2)} ms
                `;
            } else {
                resultadoForca.innerHTML = `
                    <span class="alerta">✗ Senha não encontrada.</span><br>
                    Tentativas: ${r.tentativas.toLocaleString("pt-BR")} |
                    Tempo: ${r.tempoMs.toFixed(2)} ms
                `;
            }

            infoForca.innerHTML = `
                💡 <strong>Lembrete:</strong> senhas curtas caem rápido em ataques de força bruta.
                Cada caractere a mais multiplica o esforço do atacante exponencialmente.
            `;
        } catch (e) {
            resultadoForca.innerHTML = `<span class="alerta">Erro: ${e.message}</span>`;
        } finally {
            btnForcaBruta.disabled = false;
        }
    });

    // ---------- 4. BOAS PRÁTICAS ----------
    const listaBoasPraticas = document.getElementById("listaBoasPraticas");

    // Uso de for...of para renderizar a lista
    for (const pratica of boasPraticas) {
        const li = document.createElement("li");
        li.textContent = pratica;
        listaBoasPraticas.appendChild(li);
    }
});