rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8D1F???C0 59 ?? ???? FF ??? }
        $pattern1 = { E8F7250??3A 7420 64A1 8B4068 C1E8 shr al 7510 ??}
        $pattern2 = { 83F801 7420 FF7508 push ?? FF155C01B800 call dword ptr [00B8015Ch] }

    condition:
        any of them
}