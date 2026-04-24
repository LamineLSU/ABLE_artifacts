rule Pattern1
{
    meta:
        description = "Initial test and jump to check if EAX is zero"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 0F 84 ?? ?? ?? ?? }
    condition:
        $a
}