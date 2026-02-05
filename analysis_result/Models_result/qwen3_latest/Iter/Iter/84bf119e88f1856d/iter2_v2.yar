rule Sample_Evasion
{
    meta:
        description = "Detects evasion behavior in the target sample"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 C8 ?? ?? ?? } // Push before first call
        $b = { FF 75 08 FF 15 AC B0 41 00 } // Push before ExitProcess call
        $c = { 8B FF 55 8B EC FF 75 08 } // Initial setup instructions
    condition:
        all of ($a, $b, $c)
}