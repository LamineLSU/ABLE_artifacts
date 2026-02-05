rule EvasionPatterns
{
    meta:
        description = "Detects evasion patterns through specific code sequences"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 83 C4 14 52 FF D0 }  // Add ESP, Push EDX, Call EAX (ExitProcess)
        $b = { E8 ?? ?? ?? ?? 83 C4 14 }  // Call with offset, Add ESP
        $c = { 55 8B EC 8B 45 08 8B 88 18 0A 00 00 }  // Function prologue with displacement
    condition:
        $a or $b or $c
}