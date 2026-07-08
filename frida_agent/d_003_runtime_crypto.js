
Java.perform(function() {
    // Hook Cipher.init() — detect ECB and weak key lengths
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            var algorithm = this.getAlgorithm();
            var keyBytes = key ? key.getEncoded() : null;
            var keyLength = keyBytes ? keyBytes.length * 8 : 0;
            send({agent_id:'D_003', event_type:'crypto_init',
                  algorithm: algorithm, opmode: opmode,
                  key_length: keyLength, timestamp: Date.now()});
            if (algorithm && algorithm.indexOf('ECB') !== -1) {
                send({agent_id:'D_003', event_type:'crypto_weakness',
                      weakness:'ecb_mode', algorithm: algorithm, timestamp: Date.now()});
            }
            if (keyLength > 0 && keyLength < 128 && algorithm && algorithm.indexOf('AES') !== -1) {
                send({agent_id:'D_003', event_type:'crypto_weakness',
                      weakness:'weak_key_length', key_length: keyLength, timestamp: Date.now()});
            }
            return this.init(opmode, key);
        };
    } catch(e) {
        send({agent_id:'D_003', event_type:'hook_error', error: e.message, hook:'Cipher.init'});
    }

    // Hook IvParameterSpec constructor — detect static/zero IV
    try {
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        IvParameterSpec.$init.overload('[B').implementation = function(iv) {
            var allZero = true;
            for (var i = 0; i < iv.length; i++) {
                if (iv[i] !== 0) { allZero = false; break; }
            }
            send({agent_id:'D_003', event_type:'iv_created',
                  iv_length: iv.length, is_all_zero: allZero, timestamp: Date.now()});
            if (allZero) {
                send({agent_id:'D_003', event_type:'crypto_weakness',
                      weakness:'static_zero_iv', iv_length: iv.length, timestamp: Date.now()});
            }
            return this.$init(iv);
        };
    } catch(e) {
        send({agent_id:'D_003', event_type:'hook_error', error: e.message, hook:'IvParameterSpec'});
    }

    // Hook java.util.Random — detect weak PRNG for security operations
    try {
        var Random = Java.use('java.util.Random');
        Random.nextInt.overload('int').implementation = function(bound) {
            send({agent_id:'D_003', event_type:'weak_random',
                  type:'java.util.Random', bound: bound, timestamp: Date.now()});
            return this.nextInt(bound);
        };
        Random.nextBytes.implementation = function(bytes) {
            send({agent_id:'D_003', event_type:'weak_random',
                  type:'java.util.Random', operation:'nextBytes',
                  length: bytes.length, timestamp: Date.now()});
            return this.nextBytes(bytes);
        };
    } catch(e) {
        send({agent_id:'D_003', event_type:'hook_error', error: e.message, hook:'java.util.Random'});
    }
});
