import 'package:flutter_test/flutter_test.dart';

void main() {
  // 1. normal
  // 2. with special char -- all chars + control char + left-space + right-space + .$ + ..$
  // 3. directory traversal
  // 4. confliction
  group('basic', () {
    // Read
    // ReadAll
    // Write
    // Delete
    // DeleteAll
    // ContainsKey
  });

  group('backward compatibility', () {
    // Read
    // ReadAll
    // ContainsKey
  });

  group('confiction', () {
    // Read/Write
  });

  group('directory traversal', () {
    // read/write -- product name
    // read/write -- comapany name
    // Read/Write -- key
  });
}
