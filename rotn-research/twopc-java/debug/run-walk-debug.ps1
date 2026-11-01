$Jdk = 'C:\Program Files\Eclipse Adoptium\jdk-11.0.32.101-hotspot\bin'
$R = 'c:\Users\jeren\Documents\KAMANU\ROTN\twopc-java'
& "$Jdk\javac.exe" --release 8 -cp "$R\build\probe-agent.jar" -d "$R\debug\out" "$R\debug\WalkDebug.java"
if ($LASTEXITCODE -ne 0) { throw 'debug compile failed' }
& "$Jdk\java.exe" -cp "$R\build\probe-agent.jar;$R\debug\out" WalkDebug "$R\build\classes\com\rot\n\twopc\Bus.class"