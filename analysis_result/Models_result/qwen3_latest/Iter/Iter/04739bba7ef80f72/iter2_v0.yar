rule MaliciousBehavior
{
    meta:
        description = "Detects a malicious behavior pattern involving conditional checks and ExitProcess call"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-15"

    strings:
        $a = { 85 C0 74 0E }  // Conditional check
        $b = { 6A 00 FF 15 14 28 43 00 }  // Push 0 and call ExitProcess
        $c = { B9 F8 26 43 00 }  // Memory initialization

    condition:
        all of ($a, $b, $c)
}