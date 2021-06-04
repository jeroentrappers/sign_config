
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('end2end', () async {

    // create signing / verification keys here:
    // https://mkjwk.org/. For this test i've used ES512. The public + private keys go in sign.jwk, only the public goes into verify.jwk

    // run on the command line:
    // dart run sign_config sign -i test/assets/example.json -s test/assets/sign.jwk -o out
    var p0 = await Process.run('pwd', []);
    expect(p0.exitCode, 0);
    print(p0.stdout);

    var p1 = await Process.run('dart', ['run', 'sign_config', 'sign', '-i', 'test/assets/example.json', '-s', 'test/assets/sign.jwk', '-o', 'out']);

    expect(p1.exitCode, 0);
    // then to verify and decode the result:
    // dart run sign_config verify -i out -v test/assets/verify.jwk -o result.json

    var p2 = await Process.run('dart', ['run', 'sign_config', 'verify', '-i', 'out', '-v', 'test/assets/verify.jwk', '-o', 'result.json']);

    expect(p2.exitCode, 0);
    var result = await File('result.json').readAsString();
    jsonDecode(result);

    var input = await File('test/assets/example.json').readAsString();

    expect(result, input);
    //output.json should match example.json.
  });
}
