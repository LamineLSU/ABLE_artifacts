rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? ?? ?? E8 ?? ?? ?? ?? } // generic call instruction
        $pattern1 = { 3D ?? ?? ?? ?? 74 ?? 8B } // generic comparison and jump instructions
        $pattern2 = { FF 15 ?? ?? ?? ?? } // generic call instruction with register

    condition:
        any of them
}