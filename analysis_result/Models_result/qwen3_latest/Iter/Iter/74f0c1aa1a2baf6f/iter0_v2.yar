rule Pattern0
{
    meta:
        description = "Initial check for quotes leading to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 75 ?? 41 8A 11 84 D2 74 11 }
    condition:
        $a
}