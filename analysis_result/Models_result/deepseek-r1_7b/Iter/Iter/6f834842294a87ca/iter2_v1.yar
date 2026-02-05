rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - detects and bypasss exit process using conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F7 FF ?? ?? ?? ?? FF ?? } // Call to ExitProcess and conditional jump
        $pattern1 = { ?? ?? ?? ?? E8 C8 FF FF FF ?? 00 40 E7 C3 } // Conditional check before exit decision
        $pattern2 = { ?? ?? 6D 15 AC B0 41 00 ?? ?? ?? } // Unique instruction sequence for timing bypass

    condition:
        any of them
}