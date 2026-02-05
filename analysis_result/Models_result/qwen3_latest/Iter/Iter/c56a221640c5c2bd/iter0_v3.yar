rule Pattern1
{
    meta:
        description = "Call to 0041F143h with offset masked"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 50 E8 ?? ?? ?? ?? }
    condition:
        $a
}