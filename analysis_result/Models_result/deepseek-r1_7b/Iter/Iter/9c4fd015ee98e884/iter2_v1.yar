rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target specific exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF C8 FF F0 ?? ?? ?? ?? E8 C8 FF FF }  // Match exit call with optional offset
        $pattern1 = { 8B EC FF C8 FF F0 ?? ?? ?? ?? FF 15 AC B0 41 00 }  // Add conditional check before exit

    condition:
        any of them
}