import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_windows/flutter_secure_storage_windows.dart';

// testing application.
void main() {
  runApp(const MyApp());
}

// TODO: text for key, value, result, log, product name, company name,
// TODO: action button read, read-all, write, delete, delete-all, containskey, old-write, roundtrip-with-special-chars

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String platformVersion = 'Unknown';
  final _flutterSecureStorageWindowsPlugin = FlutterSecureStorageWindows();
  final GlobalKey<FormFieldState<String>> _keyFieldKey = GlobalKey();

  bool? success;
  String? resultDetail;
  String? company;
  String? product;

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    String platformVersion;
    // Platform messages may fail, so we use a try/catch PlatformException.
    // We also handle the message potentially returning null.
    try {
      platformVersion =
          await _flutterSecureStorageWindowsPlugin.getPlatformVersion() ??
              'Unknown platform version';
    } on PlatformException {
      platformVersion = 'Failed to get platform version.';
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      platformVersion = platformVersion;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Column(children: [
            Text('Running on: $platformVersion'),
            Text('Company   : $company'),
            Text('Product   : $product'),
            TextFormField(
              key: _keyFieldKey,
              decoration: const InputDecoration(
                label: Text('Key'),
              ),
            ),
            Row(
              children: [
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doRead());
                  },
                  child: Text('Read'),
                ),
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doReadAll());
                  },
                  child: const Text('ReadAll'),
                ),
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doContainsKey());
                  },
                  child: const Text('ContainsKey'),
                ),
              ],
            ),
            Row(
              children: [
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doWrite());
                  },
                  child: Text('Write'),
                ),
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doDelete());
                  },
                  child: Text('Delete'),
                ),
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doDeleteAll());
                  },
                  child: Text('DeleteAll'),
                ),
              ],
            ),
            Row(
              children: [
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doLegacyWrite());
                  },
                  child: Text('LegacyWrite'),
                ),
                ElevatedButton(
                  onPressed: () {
                    setResult(() => doRoundTripWithSpecialChars());
                  },
                  child: Text('RoundTripWithSpecialChars'),
                ),
              ],
            ),
            Text(
                'Result: ${success == null ? '' : success! ? 'SUCCESS' : 'FAIL'}'),
            Text('Detail: $resultDetail'),
          ]),
        ),
      ),
    );
  }

  void setResult(TestResult Function() test) {
    late final TestResult result;
    try {
      result = test();
    } catch (e, s) {
      debugPrint(e.toString());
      debugPrintStack(stackTrace: s);
      result = TestResult(success: false, detail: e.toString());
    }

    setState(() {
      success = result.success;
      resultDetail = result.detail;
    });
  }
}

class FileMetadata {
  final String productName;
  final String companyName;

  FileMetadata({
    required this.companyName,
    required this.productName,
  });
}

FileMetadata getFileMetadata() {
  throw UnimplementedError();
}

class TestResult {
  final bool success;
  final String detail;
  TestResult({
    required this.success,
    required this.detail,
  });
}

const MethodChannel _channel =
    MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

Future<TestResult> testWithSecureStorage({
  required String method,
  required String key,
  String? value,
}) async {
  switch (method) {
    // TODO:
  }
}
