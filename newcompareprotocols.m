%% D2D_KeyExchange_Verkle.m
%  Secure D2D communication: RSA vs DH vs ECDH vs ECDHE (secp256k1)
%
%  Pipeline (identical for all four protocols):
%    1. Key generation (D1 and D2)
%    2. Key exchange -> symmetric 256-bit key K at D1 and D2
%    3. Random data key (DEK) wrapped under K (AES-256-GCM); data encrypted
%       under DEK (AES-256-GCM); D2 unwraps DEK and decrypts the data
%    4. Mutual smart contract between D1 and D2 (both parties sign with K)
%    5. Block appended to a blockchain; the block's records are committed in a
%       Verkle-style tree and the root commitment is stored in the block header
%  Metrics: key-generation time, key-exchange time, total cryptographic time,
%  energy, throughput, communication overhead -> graphs.
%
%  Requirements: MATLAB R2016b+ (local functions in scripts), built-in JVM
%  (Java 8+). No toolboxes needed.     Run:  >> D2D_KeyExchange_Verkle

clear; clc; close all;

%% ------------------------- Configuration ------------------------------
cfg.N               = 20;      % number of D1->D2 transactions per protocol
cfg.payload         = 1024;    % payload size per transaction (bytes)
cfg.reuseStaticKeys = true;    % RSA/DH/ECDH reuse long-term keys; ECDHE is always fresh
cfg.powZeros        = 2;       % block "proof of work": leading hex zeros
cfg.W               = 16;      % Verkle tree branching width
cfg.printAllTx      = false;   % false: full details for tx #1 only; true: every tx
% Energy model (assumption - adjust to your device):
cfg.Pcpu = 1.0;                % W, CPU power during crypto
cfg.Etx  = 100e-9;             % J/bit transmit
cfg.Erx  = 100e-9;             % J/bit receive

protocols = {'RSA','DH','ECDH','ECDHE'};

%% ------------------------- Global context -----------------------------
fprintf('Initialising secp256k1, DH group and Verkle generators ...\n');
ctx.C   = curveInit();
ctx.dh  = dhInit();
ctx.ks  = verkleGens(ctx.C, cfg.W);
ctx.cfg = cfg;

%% ------------------------- Run experiments ----------------------------
M = struct();
for pi_ = 1:numel(protocols)
    proto = protocols{pi_};
    fprintf('\n########## Running %s (%d transactions) ##########\n', proto, cfg.N);

    runTx(proto, newState(), ctx, 0);          % warm-up (JIT/class loading), not recorded

    st = newState();
    r = struct('keygen',zeros(1,cfg.N),'keyex',zeros(1,cfg.N),'enc',zeros(1,cfg.N), ...
               'dec',zeros(1,cfg.N),'total',zeros(1,cfg.N),'energy',zeros(1,cfg.N), ...
               'thr',zeros(1,cfg.N),'comm',zeros(1,cfg.N),'chain',zeros(1,cfg.N), ...
               'ok',false(1,cfg.N));
    for k = 1:cfg.N
        [m, st, lg] = runTx(proto, st, ctx, k);
        r.keygen(k) = m.keygen;  r.keyex(k)  = m.keyex;
        r.enc(k)    = m.enc;     r.dec(k)    = m.dec;
        r.total(k)  = m.total;   r.energy(k) = m.energy;
        r.thr(k)    = m.thr;     r.comm(k)   = m.comm;
        r.chain(k)  = m.chain;   r.ok(k)     = m.ok;
        if cfg.printAllTx || k == 1
            printLog(lg, proto, k);
        else
            fprintf('%s tx %02d: total crypto %.2f ms | block #%d | verified=%d\n', ...
                    proto, k, 1e3*m.total, lg.blockIndex, m.ok);
        end
    end
    M.(proto) = r;
    fprintf('\n%s: chain length (incl. genesis) = %d, all transactions verified = %d\n', ...
            proto, numel(st.chain), all(r.ok));
end

%% ------------------------- Summary table ------------------------------
fprintf('\n=================== SUMMARY (averages per transaction) ===================\n');
fprintf('%-7s %11s %11s %15s %11s %16s %9s\n','Proto','KeyGen(ms)','KeyEx(ms)', ...
        'TotalCrypto(ms)','Energy(mJ)','Throughput(Mbps)','Comm(B)');
for pi_ = 1:numel(protocols)
    r = M.(protocols{pi_});
    fprintf('%-7s %11.3f %11.3f %15.3f %11.4f %16.4f %9.0f\n', protocols{pi_}, ...
        1e3*mean(r.keygen), 1e3*mean(r.keyex), 1e3*mean(r.total), ...
        1e3*mean(r.energy), mean(r.thr), mean(r.comm));
end

%% ------------------------- Graphs -------------------------------------
sty  = {'r-o','g-s','b-^','m-d'};
cmap = [1 0 0; 0 .6 0; 0 0 1; .8 0 .8];
txv  = 1:cfg.N;
fields = {'keygen','keyex','total','energy','thr','comm'};

% Figure 1: metrics versus number of transactions
figure('Name','D2D protocols - metrics vs transactions','Color','w','Position',[50 50 1250 700]);
titles = {'Cumulative key-generation time (ms)','Cumulative key-exchange time (ms)', ...
          'Cumulative total cryptographic time (ms)','Cumulative energy consumption (mJ)', ...
          'Throughput per transaction (Mbps)','Cumulative communication overhead (KB)'};
scale  = [1e3 1e3 1e3 1e3 1 1/1024];
for s = 1:6
    subplot(2,3,s); hold on; grid on;
    for pi_ = 1:numel(protocols)
        y = M.(protocols{pi_}).(fields{s}) * scale(s);
        if s ~= 5, y = cumsum(y); end
        plot(txv, y, sty{pi_}, 'LineWidth',1.4, 'MarkerSize',5);
    end
    xlabel('Number of transactions'); title(titles{s});
    if s == 5, set(gca,'YScale','log'); end
    if s == 1, legend(protocols,'Location','northwest'); end
end

% Figure 2: per-transaction averages (bar charts)
figure('Name','D2D protocols - average comparison','Color','w','Position',[80 80 1250 700]);
btitles = {'Avg key-generation time (ms)','Avg key-exchange time (ms)', ...
           'Avg total cryptographic time (ms)','Avg energy (mJ)', ...
           'Avg throughput (Mbps)','Communication overhead (bytes/tx)'};
bscale = [1e3 1e3 1e3 1e3 1 1];
for s = 1:6
    subplot(2,3,s); hold on; grid on;
    vals = zeros(1,numel(protocols));
    for pi_ = 1:numel(protocols)
        vals(pi_) = mean(M.(protocols{pi_}).(fields{s})) * bscale(s);
        bar(pi_, vals(pi_), 0.6, 'FaceColor', cmap(pi_,:));
        text(pi_, vals(pi_), sprintf('%.3g',vals(pi_)), 'HorizontalAlignment','center', ...
             'VerticalAlignment','bottom','FontSize',8);
    end
    set(gca,'XTick',1:numel(protocols),'XTickLabel',protocols);
    title(btitles{s});
    if s == 5, set(gca,'YScale','log'); end
end

% Figure 3: breakdown of total cryptographic time
figure('Name','Total cryptographic time breakdown','Color','w');
brk = zeros(numel(protocols),4);
for pi_ = 1:numel(protocols)
    r = M.(protocols{pi_});
    brk(pi_,:) = 1e3*[mean(r.keygen) mean(r.keyex) mean(r.enc) mean(r.dec)];
end
bar(brk,'stacked'); grid on;
set(gca,'XTickLabel',protocols);
legend({'Key generation','Key exchange','AES wrap+encrypt','AES unwrap+decrypt'},'Location','northwest');
ylabel('ms per transaction'); title('Total cryptographic time breakdown');

%% ======================================================================
%%                           LOCAL FUNCTIONS
%% ======================================================================

function st = newState()
    st = struct('k1',[],'k2',[],'chain',{{}},'leaves',{{}});
end

% ---------------------------- one transaction ---------------------------
function [m, st, lg] = runTx(proto, st, ctx, k)
    C = ctx.C; cfg = ctx.cfg;
    isEC = any(strcmp(proto,{'ECDH','ECDHE'}));
    payload = makePayload(cfg.payload, k);

    % ---- 1. Key generation ----
    tKG = 0;
    needKeys = isempty(st.k1) || ~cfg.reuseStaticKeys || strcmp(proto,'ECDHE');
    if needKeys
        t = tic;
        switch proto
            case 'RSA',  st.k1 = rsaKeyPair();       st.k2 = rsaKeyPair();
            case 'DH',   st.k1 = dhKeyPair(ctx.dh);  st.k2 = dhKeyPair(ctx.dh);
            otherwise,   st.k1 = ecKeyPair(C);       st.k2 = ecKeyPair(C);
        end
        tKG = toc(t);
    end

    % ---- 2. Key exchange ----
    t = tic;
    switch proto
        case 'RSA'      % D1 picks a random 256-bit key and sends it RSA-OAEP encrypted to D2
            Kseed = randBytes(32);
            wrapK = rsaEnc(st.k2.pub, Kseed);
            K1 = Kseed;
            K2 = rsaDec(st.k2.priv, wrapK);
            hs = numel(st.k2.pubDer) + numel(wrapK);
            sec1 = Kseed; sec2 = K2;
            fp1 = st.k1.fp; fp2 = st.k2.fp;
        case 'DH'       % classic finite-field DH (RFC 3526, 2048-bit group)
            s1 = st.k2.y.modPow(st.k1.x, ctx.dh.p);
            s2 = st.k1.y.modPow(st.k2.x, ctx.dh.p);
            sec1 = h2b(padHex(s1,512)); sec2 = h2b(padHex(s2,512));
            K1 = sha256(sec1); K2 = sha256(sec2);
            hs = 2*256;
            fp1 = sha256(h2b(padHex(st.k1.y,512))); fp2 = sha256(h2b(padHex(st.k2.y,512)));
        otherwise       % ECDH (static keys) / ECDHE (fresh keys), secp256k1
            S1 = ecMul(st.k1.d, st.k2.Q, C);
            S2 = ecMul(st.k2.d, st.k1.Q, C);
            sec1 = h2b(bi2hex256(S1.x)); sec2 = h2b(bi2hex256(S2.x));   % 256-bit shared secret
            K1 = sha256(sec1); K2 = sha256(sec2);                        % 256-bit AES key (SHA-256 KDF)
            hs = 2*33;                                                   % two compressed points
            fp1 = sha256(pt33(st.k1.Q)); fp2 = sha256(pt33(st.k2.Q));
    end
    tKE = toc(t);

    % ---- 3. D1: wrap DEK under K, encrypt data under DEK ----
    t = tic;
    DEK  = randBytes(32);
    ivW  = randBytes(12);
    wDEK = [ivW; gcmEnc(K1, ivW, DEK)];            % IV | CT | TAG  (60 bytes)
    ivD  = randBytes(12);
    ct   = gcmEnc(DEK, ivD, payload);              % CT | TAG
    tEnc = toc(t);

    % ---- 4. D2: unwrap DEK, decrypt data ----
    t = tic;
    DEK2 = gcmDec(K2, wDEK(1:12), wDEK(13:end));
    pt   = gcmDec(DEK2, ivD, ct);
    tDec = toc(t);

    ok = isequal(pt, payload) && isequal(DEK, DEK2) && isequal(K1, K2);

    % ---- 5. Smart contract + blockchain with Verkle commitments ----
    t = tic;
    id1 = ['D1-' b2h(fp1(1:4))]; id2 = ['D2-' b2h(fp2(1:4))];
    sc  = makeContract(proto, id1, id2, sha256(payload), K1, K2, k);
    if isempty(st.chain)
        gl = {sha256(uint8('genesis'))};
        gRoot = verkleCommit(gl, ctx.ks, C, cfg.W);
        st.chain{1} = mineBlock(0, repmat('0',1,64), gRoot, gRoot, repmat('0',1,64), 0, cfg);
    end
    leafH = {sha256(ct), sha256(wDEK), sha256([sc.termsHash; sc.sig1; sc.sig2])};
    blkRoot = verkleCommit(leafH, ctx.ks, C, cfg.W);            % per-block Verkle root
    st.leaves = [st.leaves, leafH];
    stRoot  = verkleCommit(st.leaves, ctx.ks, C, cfg.W);        % global state Verkle root
    txHash  = sha256([sha256(ct); sha256(wDEK); sc.termsHash]);
    prev    = st.chain{end};
    blk     = mineBlock(numel(st.chain), prev.hash, blkRoot, stRoot, b2h(txHash), numel(st.leaves), cfg);
    blk.contract = sc.address;
    st.chain{end+1} = blk;
    sc.states = [sc.states, {'DataExchanged','Settled (recorded on-chain)'}];
    tChain = toc(t);

    % ---- metrics ----
    comm  = hs + 60 + 12 + 16 + 96;   % handshake + wrapped DEK + data IV/tag + contract (hash + 2 sigs)
    total = tKG + tKE + tEnc + tDec;
    m.keygen = tKG; m.keyex = tKE; m.enc = tEnc; m.dec = tDec;
    m.total  = total; m.chain = tChain; m.comm = comm; m.ok = ok;
    m.energy = cfg.Pcpu*total + 8*comm*(cfg.Etx + cfg.Erx);
    m.thr    = (8*numel(payload)/total)/1e6;           % Mbps

    % ---- log (captured BEFORE ephemeral keys are destroyed) ----
    lg.isEC = isEC; lg.ok = ok; lg.blockIndex = blk.index;
    lg.fp1 = b2h(fp1); lg.fp2 = b2h(fp2);
    if isEC
        lg.d1 = bi2hex256(st.k1.d);       lg.d2 = bi2hex256(st.k2.d);
        lg.x1 = bi2hex256(st.k1.Q.x);     lg.y1 = bi2hex256(st.k1.Q.y);
        lg.x2 = bi2hex256(st.k2.Q.x);     lg.y2 = bi2hex256(st.k2.Q.y);
        lg.c1 = b2h(pt33(st.k1.Q));       lg.c2 = b2h(pt33(st.k2.Q));
    end
    lg.sec1 = b2h(sec1(1:min(32,end)));   lg.sec2 = b2h(sec2(1:min(32,end)));
    lg.K1 = b2h(K1); lg.K2 = b2h(K2);
    lg.DEK = b2h(DEK); lg.wDEK = b2h(wDEK); lg.DEK2 = b2h(DEK2);
    lg.pt = b2h(payload(1:32)); lg.ct = b2h(ct(1:32)); lg.dec = b2h(pt(1:32));
    lg.ctLen = numel(ct); lg.ptTxt = char(payload(1:24).');
    lg.sc = sc; lg.blk = blk; lg.m = m;

    if strcmp(proto,'ECDHE'), st.k1 = []; st.k2 = []; end     % ephemeral keys destroyed
end

% ------------------------------ printing --------------------------------
function printLog(lg, proto, k)
    fprintf('\n==================== %s | Transaction %d ====================\n', proto, k);
    if lg.isEC
        fprintf('[D1] Private key (256-bit)      : %s\n', lg.d1);
        fprintf('[D1] Public key X (256-bit)     : %s\n', lg.x1);
        fprintf('[D1] Public key Y (256-bit)     : %s\n', lg.y1);
        fprintf('[D1] Public key (compressed 33B): %s\n', lg.c1);
        fprintf('[D2] Private key (256-bit)      : %s\n', lg.d2);
        fprintf('[D2] Public key X (256-bit)     : %s\n', lg.x2);
        fprintf('[D2] Public key Y (256-bit)     : %s\n', lg.y2);
        fprintf('[D2] Public key (compressed 33B): %s\n', lg.c2);
        fprintf('Shared secret at D1 (256-bit)   : %s\n', lg.sec1);
        fprintf('Shared secret at D2 (256-bit)   : %s\n', lg.sec2);
        fprintf('Shared secret match             : %d\n', strcmp(lg.sec1, lg.sec2));
    else
        fprintf('[D1] key fingerprint (SHA-256)  : %s\n', lg.fp1);
        fprintf('[D2] key fingerprint (SHA-256)  : %s\n', lg.fp2);
        fprintf('(%s keys are not 256-bit; only the fingerprints are shown)\n', proto);
    end
    fprintf('AES-256 session key at D1       : %s\n', lg.K1);
    fprintf('AES-256 session key at D2       : %s\n', lg.K2);
    fprintf('Data key DEK (plain, 256-bit)   : %s\n', lg.DEK);
    fprintf('Encrypted DEK (IV|CT|TAG, 60 B) : %s\n', lg.wDEK);
    fprintf('Decrypted DEK at D2 (256-bit)   : %s\n', lg.DEK2);
    fprintf('Plaintext  (first 32 B)         : %s  ("%s...")\n', lg.pt, lg.ptTxt);
    fprintf('Ciphertext (first 32 B)         : %s  (total %d B incl. 16 B GCM tag)\n', lg.ct, lg.ctLen);
    fprintf('Decrypted  (first 32 B)         : %s\n', lg.dec);
    fprintf('Decryption / integrity verified : %d\n', lg.ok);

    sc = lg.sc;
    fprintf('\n--- Smart contract (mutual, D1 <-> D2) ---\n');
    fprintf('Contract address   : %s\n', sc.address);
    fprintf('Party D1           : %s\n', sc.id1);
    fprintf('Party D2           : %s\n', sc.id2);
    fprintf('Key-exchange proto : %s\n', sc.proto);
    fprintf('Terms hash         : %s\n', b2h(sc.termsHash));
    fprintf('Payload hash       : %s\n', b2h(sc.dataHash));
    fprintf('Signature D1 (HMAC): %s\n', b2h(sc.sig1));
    fprintf('Signature D2 (HMAC): %s\n', b2h(sc.sig2));
    fprintf('D2 verifies D1 sig : %d | D1 verifies D2 sig : %d\n', sc.v1, sc.v2);
    fprintf('State history      : %s\n', strjoin(sc.states, ' -> '));

    b = lg.blk;
    fprintf('\n--- Block details ---\n');
    fprintf('Block index        : %d\n', b.index);
    fprintf('Timestamp          : %s\n', b.time);
    fprintf('Previous hash      : %s\n', b.prev);
    fprintf('Tx hash            : %s\n', b.txHash);
    fprintf('Verkle root commitment (block, compressed) : %s\n', b.root);
    fprintf('Verkle root commitment (state, compressed) : %s\n', b.stateRoot);
    fprintf('Records in state tree : %d | Contract : %s\n', b.nLeaves, b.contract);
    fprintf('Nonce              : %d\n', b.nonce);
    fprintf('Block hash         : %s\n', b.hash);

    m = lg.m;
    fprintf('\n--- Metrics (this transaction) ---\n');
    fprintf('Key generation %.3f ms | Key exchange %.3f ms | Enc %.3f ms | Dec %.3f ms\n', ...
            1e3*m.keygen, 1e3*m.keyex, 1e3*m.enc, 1e3*m.dec);
    fprintf('Total crypto %.3f ms | Energy %.4f mJ | Throughput %.4f Mbps | Comm overhead %d B\n', ...
            1e3*m.total, 1e3*m.energy, m.thr, m.comm);
    fprintf('Smart-contract + blockchain time %.3f ms (not included in total crypto time)\n', 1e3*m.chain);
end

% --------------------------- smart contract -----------------------------
function sc = makeContract(proto, id1, id2, dataHash, K1, K2, k)
    terms = sprintf('%s|%s|%s|%s|tx%d', proto, id1, id2, b2h(dataHash), k);
    sc.termsHash = sha256(uint8(terms));
    a = sha256([sc.termsHash; reshape(uint8('contract'),[],1)]);
    sc.address = ['0x' b2h(a(1:20))];
    sc.id1 = id1; sc.id2 = id2; sc.proto = proto; sc.dataHash = dataHash;
    t1 = reshape(uint8('D1:'),[],1);
    t2 = reshape(uint8('D2:'),[],1);
    sc.sig1 = hmac256(K1, [t1; sc.termsHash]);                      % D1 accepts
    sc.sig2 = hmac256(K2, [t2; sc.termsHash]);                      % D2 accepts
    sc.v1 = isequal(hmac256(K2, [t1; sc.termsHash]), sc.sig1);      % D2 checks D1
    sc.v2 = isequal(hmac256(K1, [t2; sc.termsHash]), sc.sig2);      % D1 checks D2
    sc.states = {'Deployed','Accepted by D1','Accepted by D2','Active'};
    if ~(sc.v1 && sc.v2), error('Smart contract signature verification failed'); end
end

% ------------------------------ blockchain ------------------------------
function blk = mineBlock(idx, prevHash, rootBytes, stateBytes, txHashHex, nLeaves, cfg)
    blk.index = idx; blk.prev = prevHash; blk.txHash = txHashHex; blk.nLeaves = nLeaves;
    blk.root = b2h(rootBytes); blk.stateRoot = b2h(stateBytes);
    blk.time = char(datetime('now','Format','yyyy-MM-dd HH:mm:ss.SSS')); blk.contract = '-';
    prefix = repmat('0', 1, cfg.powZeros);
    nonce = 0;
    while true
        hdr = sprintf('%d|%s|%s|%s|%s|%s|%d', idx, prevHash, blk.root, blk.stateRoot, txHashHex, blk.time, nonce);
        h = b2h(sha256(uint8(hdr)));
        if strncmp(h, prefix, numel(prefix)), break; end
        nonce = nonce + 1;
    end
    blk.nonce = nonce; blk.hash = h;
end

% Verkle-style tree: every node commits to its W children with a vector
% (Pedersen) commitment on secp256k1:  C = sum_i m_i * G_i,  G_i = k_i * G.
% Child values are m = H(commitment) mod n.  Returns the 33-byte compressed root.
% NOTE: k_i are public here (demo), so this is NOT binding in the cryptographic
% sense; real Verkle trees use KZG/IPA commitments with unknown discrete logs.
function root = verkleCommit(leafHashes, ks, C, W)
    level = cell(1, numel(leafHashes));
    for i = 1:numel(leafHashes)
        level{i} = java.math.BigInteger(1, toJ(leafHashes{i})).mod(C.n);
    end
    while true
        nG = ceil(numel(level) / W);
        nxt = cell(1, nG);
        for g = 1:nG
            idx = (g-1)*W+1 : min(g*W, numel(level));
            s = C.zero;
            for j = 1:numel(idx)
                s = s.add(level{idx(j)}.multiply(ks{j}));
            end
            s = s.mod(C.n);
            if s.signum() == 0, s = C.one; end
            Pt = ecMul(s, C.G, C);
            nxt{g} = java.math.BigInteger(1, toJ(sha256([h2b(bi2hex256(Pt.x)); h2b(bi2hex256(Pt.y))]))).mod(C.n);
        end
        if nG == 1, root = pt33(Pt); return; end
        level = nxt;
    end
end

function ks = verkleGens(C, W)
    ks = cell(1, W);
    for i = 1:W
        ks{i} = java.math.BigInteger(1, toJ(sha256(uint8(sprintf('verkle-gen-%d', i))))).mod(C.n);
    end
end

% ------------------------- secp256k1 arithmetic -------------------------
function C = curveInit()
    BI = @(h) java.math.BigInteger(h, 16);
    C.p  = BI(['FFFFFFFF','FFFFFFFF','FFFFFFFF','FFFFFFFF','FFFFFFFF','FFFFFFFF','FFFFFFFE','FFFFFC2F']);
    C.n  = BI(['FFFFFFFF','FFFFFFFF','FFFFFFFF','FFFFFFFE','BAAEDCE6','AF48A03B','BFD25E8C','D0364141']);
    gx   = BI(['79BE667E','F9DCBBAC','55A06295','CE870B07','029BFCDB','2DCE28D9','59F2815B','16F81798']);
    gy   = BI(['483ADA77','26A3C465','5DA4FBFC','0E1108A8','FD17B448','A6855419','9C47D08F','FB10D4B8']);
    C.G   = struct('x', gx, 'y', gy, 'inf', false);
    C.inf = struct('x', [], 'y', [], 'inf', true);
    C.zero = java.math.BigInteger('0'); C.one = java.math.BigInteger('1');
    C.three = java.math.BigInteger('3');
    % self-test: G on curve (y^2 = x^3 + 7) and n*G = infinity
    lhs = gy.multiply(gy).mod(C.p);
    rhs = gx.pow(3).add(java.math.BigInteger('7')).mod(C.p);
    if ~lhs.equals(rhs), error('secp256k1 generator is not on the curve'); end
    nG = ecMul(C.n, C.G, C);
    if ~nG.inf, error('secp256k1 self-test failed: n*G is not infinity'); end
end

function R = ecAdd(P, Q, C)
    if P.inf, R = Q; return; end
    if Q.inf, R = P; return; end
    p = C.p;
    if P.x.equals(Q.x)
        if ~P.y.equals(Q.y) || P.y.signum() == 0
            R = C.inf; return;
        end
        lam = P.x.multiply(P.x).multiply(C.three).multiply(P.y.shiftLeft(1).modInverse(p)).mod(p);
    else
        lam = Q.y.subtract(P.y).multiply(Q.x.subtract(P.x).mod(p).modInverse(p)).mod(p);
    end
    x3 = lam.multiply(lam).subtract(P.x).subtract(Q.x).mod(p);
    y3 = lam.multiply(P.x.subtract(x3)).subtract(P.y).mod(p);
    R = struct('x', x3, 'y', y3, 'inf', false);
end

function R = ecMul(k, P, C)          % double-and-add
    R = C.inf;
    for i = double(k.bitLength())-1 : -1 : 0
        R = ecAdd(R, R, C);
        if k.testBit(i), R = ecAdd(R, P, C); end
    end
end

function kp = ecKeyPair(C)
    sr = getSR();
    kp.d = java.math.BigInteger(256, sr).mod(C.n.subtract(C.one)).add(C.one);   % 1..n-1
    kp.Q = ecMul(kp.d, C.G, C);
end

function b = pt33(P)                 % compressed point: 02/03 || X
    b = [uint8(2 + double(P.y.testBit(0))); h2b(bi2hex256(P.x))];
end

% ----------------------------- classic DH -------------------------------
function dh = dhInit()               % RFC 3526 group 14 (2048-bit MODP), g = 2
    hx = ['FFFFFFFF','FFFFFFFF','C90FDAA2','2168C234','C4C6628B','80DC1CD1','29024E08','8A67CC74', ...
          '020BBEA6','3B139B22','514A0879','8E3404DD','EF9519B3','CD3A431B','302B0A6D','F25F1437', ...
          '4FE1356D','6D51C245','E485B576','625E7EC6','F44C42E9','A637ED6B','0BFF5CB6','F406B7ED', ...
          'EE386BFB','5A899FA5','AE9F2411','7C4B1FE6','49286651','ECE45B3D','C2007CB8','A163BF05', ...
          '98DA4836','1C55D39A','69163FA8','FD24CF5F','83655D23','DCA3AD96','1C62F356','208552BB', ...
          '9ED52907','7096966D','670C354E','4ABC9804','F1746C08','CA18217C','32905E46','2E36CE3B', ...
          'E39E772C','180E8603','9B2783A2','EC07A28F','B5C55DF0','6F4C52C9','DE2BCBF6','95581718', ...
          '3995497C','EA956AE5','15D22618','98FA0510','15728E5A','8AACAA68','FFFFFFFF','FFFFFFFF'];
    dh.p = java.math.BigInteger(hx, 16);
    dh.g = java.math.BigInteger('2');
    if ~(dh.p.isProbablePrime(20) && dh.p.shiftRight(1).isProbablePrime(20))
        error('DH prime failed the safe-prime check (hex constant mistyped?)');
    end
end

function kp = dhKeyPair(dh)
    kp.x = java.math.BigInteger(256, getSR());      % 256-bit private exponent
    if kp.x.signum() == 0, kp.x = java.math.BigInteger('1'); end
    kp.y = dh.g.modPow(kp.x, dh.p);
end

% -------------------------------- RSA -----------------------------------
function kp = rsaKeyPair()
    g = java.security.KeyPairGenerator.getInstance('RSA');
    g.initialize(int32(2048));
    j = g.generateKeyPair();
    kp.pub = j.getPublic(); kp.priv = j.getPrivate();
    kp.pubDer = typecast(kp.pub.getEncoded(), 'uint8'); kp.pubDer = kp.pubDer(:);
    kp.fp = sha256(kp.pubDer);
end

function c = rsaEnc(pub, m)
    ci = javax.crypto.Cipher.getInstance('RSA/ECB/OAEPWithSHA-256AndMGF1Padding');
    ci.init(1, pub);
    c = typecast(ci.doFinal(toJ(m)), 'uint8'); c = c(:);
end

function m = rsaDec(priv, c)
    ci = javax.crypto.Cipher.getInstance('RSA/ECB/OAEPWithSHA-256AndMGF1Padding');
    ci.init(2, priv);
    m = typecast(ci.doFinal(toJ(c)), 'uint8'); m = m(:);
end

% ------------------------------- AES-GCM --------------------------------
function ct = gcmEnc(key, iv, pt)
    ci = javax.crypto.Cipher.getInstance('AES/GCM/NoPadding');
    ci.init(1, javax.crypto.spec.SecretKeySpec(toJ(key), 'AES'), ...
               javax.crypto.spec.GCMParameterSpec(int32(128), toJ(iv)));
    ct = typecast(ci.doFinal(toJ(pt)), 'uint8'); ct = ct(:);
end

function pt = gcmDec(key, iv, ct)
    ci = javax.crypto.Cipher.getInstance('AES/GCM/NoPadding');
    ci.init(2, javax.crypto.spec.SecretKeySpec(toJ(key), 'AES'), ...
               javax.crypto.spec.GCMParameterSpec(int32(128), toJ(iv)));
    pt = typecast(ci.doFinal(toJ(ct)), 'uint8'); pt = pt(:);
end

% ------------------------------ utilities -------------------------------
function h = sha256(x)
    md = java.security.MessageDigest.getInstance('SHA-256');
    h = typecast(md.digest(toJ(x)), 'uint8'); h = h(:);
end

function h = hmac256(key, msg)
    mac = javax.crypto.Mac.getInstance('HmacSHA256');
    mac.init(javax.crypto.spec.SecretKeySpec(toJ(key), 'HmacSHA256'));
    h = typecast(mac.doFinal(toJ(msg)), 'uint8'); h = h(:);
end

function j = toJ(x)                  % MATLAB bytes -> Java byte[]
    j = typecast(uint8(x(:)), 'int8');
end

function sr = getSR()
    persistent s
    if isempty(s), s = java.security.SecureRandom(); end
    sr = s;
end

function b = randBytes(n)
    h = lower(char(java.math.BigInteger(8*n, getSR()).toString(16)));
    h = [repmat('0', 1, 2*n - numel(h)) h];
    b = h2b(h);
end

function h = b2h(b)
    h = upper(reshape(dec2hex(double(b(:)), 2).', 1, []));
end

function b = h2b(h)
    h = h(:).';
    b = uint8(hex2dec(reshape(h, 2, []).'));
    b = b(:);
end

function h = bi2hex256(b)            % BigInteger -> 64 hex chars (256-bit)
    h = padHex(b, 64);
end

function h = padHex(b, nHex)
    h = upper(char(b.toString(16)));
    h = [repmat('0', 1, nHex - numel(h)) h];
end

function p = makePayload(n, k)
    hdr = uint8(sprintf('D1->D2 tx%03d sensor: ', k));
    body = uint8(mod((1:(n - numel(hdr))) * 7 + k, 256));
    p = [hdr(:); body(:)];
end