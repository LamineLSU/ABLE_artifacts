rule Evasion_Exit_Calls
{
    meta:
        description = "Detects potential evasion through process termination or control flow obfuscation."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { FF 75 08 E8 C8 FF FF FF }
        $b = { FF 15 AC B0 41 00 }
        $c = { 8B EC 59 FF 75 08 }

    condition:
        any of ($a, $b, $c)
}