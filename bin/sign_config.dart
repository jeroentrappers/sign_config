import 'package:sign_config/sign_config.dart';

Future<int> main(List<String> arguments) async {
  var args = setupCLI().parse(arguments);
  try {
    switch(args.command?.name){
      case sign:
        return await signImpl(args);
      case verify:
        return await verifyImpl(args);
    }

  } on Error catch (e) {
    if (args['verbose']) print(e);
  }
  return 1;
}






