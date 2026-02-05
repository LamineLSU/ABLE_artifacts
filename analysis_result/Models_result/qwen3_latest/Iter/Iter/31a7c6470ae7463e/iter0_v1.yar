rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 2D 92 F6 80 74 CF }  // CMP eax, 0x80F6922D + JE
        $pattern1 = { 52 FF D0 5E }             // Push edx + Call eax + Pop esi
        $pattern2 = { 52 E8 ?? ?? ?? ?? }      // Push edx + Call (displacement)

    condition:
        all of them
}