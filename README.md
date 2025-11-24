# Build project
```bash
./gradlew build
```
# Run static analyzer
```bash
./gradlew run runMain --args="--options-file=java-benchmarks/JDV/test.yml"
```
# Run dynamic analyzer
```bash
./gradlew run runDynamicTester --args="--options-file=java-benchmarks/JDV/test.yml"
```
