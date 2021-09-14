
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:convert/convert.dart';

void main() {
  test('end2end', () async {

    // create signing / verification keys here:
    // https://mkjwk.org/. For this test i've used ES512. The public + private keys go in sign.jwk, only the public goes into verify.jwk

    // run on the command line:
    // dart run sign_config sign -i test/assets/example.json -s test/assets/sign.jwk -o out
    var p0 = await Process.run('pwd', []);
    expect(p0.exitCode, 0);
    print(p0.stdout);

    var p1 = await Process.run('dart', ['run', 'sign_config', 'sign', '-i', 'test/assets/example.json', '-s', 'test/assets/sign.jwk', '-o', 'out.signed', '-V']);
    print(p1.stdout);
    expect(p1.exitCode, 0);
    // then to verify and decode the result:
    // dart run sign_config verify -i out -v test/assets/verify.jwk -o result.json

    var p2 = await Process.run('dart', ['run', 'sign_config', 'verify', '-i', 'out.signed', '-v', 'test/assets/verify.jwk', '-o', 'result.verified.json', '-V']);
    print(p2.stdout);
    expect(p2.exitCode, 0);
    var result = await File('result.verified.json').readAsString();
    jsonDecode(result);

    var input = await File('test/assets/example.json').readAsString();

    expect(result, input);

    // create encryption / decryption keys here:
    // https://mkjwk.org/. For this test i've used P-512. The public + private keys go in decrypt.jwk, only the public goes into encrypt.jwk
    // run on the command line:
    // dart run sign_config encrypt -i test/assets/example.json -s test/assets/encrypt.jwk -o out
    var p3 = await Process.run('dart', ['run', 'sign_config', 'encrypt', '-i', 'test/assets/example.json', '-e', 'test/assets/encrypt.jwk', '-o', 'out.encrypted', '-V']);
    print(p3.stdout);
    expect(p3.exitCode, 0);

    // then to decrypt the result:
    // dart run sign_config verify -i out -v test/assets/verify.jwk -o result.json
    var p4 = await Process.run('dart', ['run', 'sign_config', 'decrypt', '-i', 'out.encrypted', '-d', 'test/assets/decrypt.jwk', '-o', 'result.decrypted.json', '-V']);
    print(p4.stdout);
    expect(p4.exitCode, 0);
    var decrypted = await File('result.decrypted.json').readAsString();
    jsonDecode(decrypted);
    expect(result, input);

    //output.json should match example.json.
  });

  test('zlib null compression', () async {

    var input = File('test/assets/example.json');
    //var raw = await input.readAsBytes();

    var raw = hex.decode(r'd2844da2012604485f74910195c5cecba059012ca401625345041a60e032ca061a60c877cb390103a101a4617481a9626369782255524e3a555643493a30313a53453a45484d2f5441524e383938373534333938373762636f625345626973765377656469736820654865616c7468204167656e6379626e6d76526f636865204c696768744379636c65722071504352627363c074323032312d30362d31355430393a32343a30325a627463781e41726c616e646120416972706f727420436f7669642043656e74657220316274676938343035333930303662747269323630343135303030627474684c50363436342d3463646f626a313935382d31312d3131636e616da462666e6a4cc3b676737472c3b66d62676e654f7363617263666e746a4c4f45565354524f454d63676e74654f534341526376657265312e332e3058409d8f9ec86555795cf2bdb22d5384e0b0a12ecf8b9f9436950149e12f4f85675dcc038a12dc6c696af1fa910801d3e58525c8f3028a24fa84318bd39fde50ee00');

    print('raw size: ' + raw.length.toString());
    var zipped = ZLibCodec(raw: false, gzip: false, memLevel: ZLibOption.minMemLevel, level: ZLibOption.maxLevel, strategy: ZLibOption.strategyRle).encoder.convert(raw);
    print('zipped size: ' + zipped.length.toString());
  });
}