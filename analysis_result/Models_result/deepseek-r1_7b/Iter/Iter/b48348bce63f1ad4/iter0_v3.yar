rule Bypass_Sample
{
    meta:
        description = "Evasion bypass over multiple conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F8 ?? ?? 7D 9E ?? FF C8 36 7A 04 ?? } <!-- Jump from offset 0x7E to 0x3F7C -->
        $pattern1 = { E8 C1 FF FF 8B 45 8C 51 82 8D FF CA FF D9 71 6F 8A 04 FF } <!-- Jump from offset 0x0 to 0x0000007Eh via 0x30h -->
        $pattern2 = { 8B C5 F8 ?? ?? FF 0A 7D FD FF FF 1F 6E 7C 4E 79 FF } <!-- Jump from offset 0x0 to 0x0000007Ah via 0x3Ch -->

    condition:
        any of them
}