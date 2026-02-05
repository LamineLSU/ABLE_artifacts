rule Evolved_Detection
{
    meta:
        description = "Detects obfuscated conditional checks and ExitProcess calls in the trace"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
        confidence = high

    strings:
        $a = { FF 15 ?? 63 45 00 } 83F820  // ShellExecuteW call + cmp eax, 20h
        $b = { FF 15 70 62 45 00 }      // ExitProcess call
        $c = 84C0 742A            // test al, al + je

    condition:
        all of ($a, $b, $c)
}