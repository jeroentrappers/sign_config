import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:jose/jose.dart';

const inputFile = 'input-file';
const outputFile = 'output-file';

const signingCert = 'signing-cert';
const verifyCert = 'verify-cert';

const encryptCert = 'encrypt-cert';
const decryptCert = 'decrypt-cert';

const sign = 'sign';
const verify = 'verify';
const encrypt = 'encrypt';
const decrypt = 'decrypt';

ArgParser setupCLI() {
  var signCommand = ArgParser()
    ..addOption(inputFile, abbr: 'i', help: 'provide the input file (payload) which needs to be signed', mandatory: true)
    ..addOption(signingCert, abbr: 's', help: 'provide the signing certificate', mandatory: true)
    ..addOption(outputFile, abbr: 'o', help: 'where to put the signed payload', mandatory: true);

  var verifyCommand = ArgParser()
    ..addOption(inputFile, abbr: 'i', help: 'provide the signed file to be verified', mandatory: true)
    ..addOption(verifyCert, abbr: 'v', help: 'provide the cert (public key) to verify the signature.', mandatory: true)
    ..addOption(outputFile, abbr: 'o', help: 'where to put the verified payload', mandatory: true);

  var encryptCommand = ArgParser()
    ..addOption(inputFile, abbr: 'i', help: 'provide the input file (payload) which needs to be encrypted', mandatory: true)
    ..addOption(encryptCert, abbr: 'e', help: 'provide the encryption key (private)', mandatory: true)
    ..addOption(outputFile, abbr: 'o', help: 'where to put the encrypted payload', mandatory: true);

  var decryptCommand = ArgParser()
    ..addOption(inputFile, abbr: 'i', help: 'provide the encrypted file to be decrypted', mandatory: true)
    ..addOption(decryptCert, abbr: 'd', help: 'provide the decryption key (public)', mandatory: true)
    ..addOption(outputFile, abbr: 'o', help: 'where to put the decrypted payload', mandatory: true);

  final parser = ArgParser()
    ..addCommand(sign, signCommand)
    ..addCommand(verify, verifyCommand)
    ..addCommand(encrypt, encryptCommand)
    ..addCommand(decrypt, decryptCommand)
    ..addFlag('verbose', abbr: 'V', defaultsTo: false);
  return parser;
}

Future<int> signImpl(ArgResults args) async {
  try {
    var input = File(args.command?[inputFile]);
    var output = File(args.command?[outputFile]);

    var raw = await input.readAsBytes();

    print('raw size: ' + raw.length.toString());
    var zipped = ZLibCodec(level: ZLibOption.maxLevel).encoder.convert(raw);
    print('zipped size: ' + zipped.length.toString());

    var cert = File(args.command?[signingCert]);
    var key = await cert.readAsString();
    var jwk = JsonWebKey.fromJson(jsonDecode(key));

    var builder = JsonWebSignatureBuilder()
      ..data = zipped
      ..addRecipient(jwk);

    var jws = builder.build();
    await output.writeAsString(jws.toCompactSerialization());
    return 0;
  } on JoseException catch (e) {
    if (args['verbose']) print(e);
    return -1;
  }
}

Future<int> verifyImpl(ArgResults args) async {
  try {
    var input = File(args.command?[inputFile]);
    var output = File(args.command?[outputFile]);

    var encoded = await input.readAsString();
    var jws = JsonWebSignature.fromCompactSerialization(encoded);

    var cert = File(args.command?[verifyCert]);
    var jwkJson = await cert.readAsString();
    var jwk = JsonWebKey.fromJson(jsonDecode(jwkJson));

    var keyStore = JsonWebKeyStore()..addKey(jwk);

    var payload = await jws.getPayload(keyStore);
    var unzipped = ZLibCodec(level: ZLibOption.maxLevel).decoder.convert(payload.data);
    await output.writeAsBytes(unzipped);
    return 0;
  } on JoseException catch (e) {
    if (args['verbose']) print(e);
    return -1;
  }
}

Future<int> encryptImpl(ArgResults args) async {
  try {
    var input = File(args.command?[inputFile]);
    var output = File(args.command?[outputFile]);

    var raw = await input.readAsBytes();

    print('raw size: ' + raw.length.toString());
    var zipped = ZLibCodec(level: ZLibOption.maxLevel).encoder.convert(raw);
    print('zipped size: ' + zipped.length.toString());

    var cert = File(args.command?[encryptCert]);
    var key = await cert.readAsString();
    var jwk = JsonWebKey.fromJson(jsonDecode(key));
    var builder = JsonWebEncryptionBuilder()
      ..data = zipped
      ..addRecipient(jwk);

    var jwe = builder.build();
    await output.writeAsString(jwe.toCompactSerialization());
    return 0;
  } on JoseException catch (e) {
    if (args['verbose']) print(e);
    return -1;
  }
}

Future<int> decryptImpl(ArgResults args) async {
  try {
    var input = File(args.command?[inputFile]);
    var output = File(args.command?[outputFile]);

    var encoded = await input.readAsString();
    var jwe = JsonWebEncryption.fromCompactSerialization(encoded);

    var cert = File(args.command?[decryptCert]);
    var jwkJson = await cert.readAsString();
    var jwk = JsonWebKey.fromJson(jsonDecode(jwkJson));

    var keyStore = JsonWebKeyStore()..addKey(jwk);

    var payload = await jwe.getPayload(keyStore);
    var unzipped = ZLibCodec(level: ZLibOption.maxLevel).decoder.convert(payload.data);
    await output.writeAsBytes(unzipped);
    return 0;
  } on JoseException catch (e) {
    if (args['verbose']) print(e);
    return -1;
  }
}