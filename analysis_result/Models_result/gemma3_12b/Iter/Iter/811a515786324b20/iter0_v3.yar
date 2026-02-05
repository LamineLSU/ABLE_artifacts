rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 94 FD FF FF BA 03 00 00 00 E8 F5 B9 FE FF }  // Around call 00403E1Ch
        $pattern1 = { 8B 85 94 FD FF FF E8 3D FF FF 89 85 E8 FE FF FF }  // Around call 00403D3Ch
        $pattern2 = { 8D 95 78 FD FF FF 33 C0 E8 D1 88 FE FF 8B 95 78 FD FF FF }  // Around call eax

    condition:
        any of them
}