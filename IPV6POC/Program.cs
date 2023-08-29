using System;
using System.Text.RegularExpressions;
using System.Net;
using System.Collections.Generic;

namespace IPV6POC
{
    class Program
    {

        static void Main()
        {

            string[] ipv6Addresses = {
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001:0db8:85a3::8a2e:0370:7334",
                "2001:0db8:85a3:0:0:8a2e:0370:7334/48",
                "2001:0db8:85a3:0::8a2e:0370:7334",
                "::1",
                "fe80::1",
                "fd00:3453:d2f3:6987::1743",
                "fe80::50f2:f789:4d83:4bbc%7",
                "fe80::3653:d2ff:fef3:6989%7",
                "ff06::c3",
                "1050:0:0:0:5:600:300c:326b",
                "1050:0000:0000:0000:0005:0600:300c:326b",
                "0:0:0:0:0:ffff:192.1.56.10",
                "2001::",
                "2001::1",
                "2001:0db8::",
                "2001:0db8::1",
                "::",
                "0:0:0:0:0:0:0:1",
                "2001:0db8:85a3:00000:0000:8a2e:0370:7334",
                "invalid_ipv6_address"
            };

            string[] validIPv6Addresses =
            {
                "::",
                "::1",
                "::ffff:192.0.2.128",
                "0:0:0:0:0:0:0:1",
                "1050:0:0:0:5:600:300c:1",
                "2001::1",
                "2001:0:9D38:953C:10EF:EE22:FFDD:AABB",
                "2001:0DA8:0200:0012:0000:00B8:0000:02AA",
                "2001:0db8::1",
                "2001:0db8::1:0:0:1",
                "2001:0DB8::4152:EBAF:CE01:0001",
                "2001:0db8:0:0:1:0:0:1",
                "2001:0DB8:0000:CD30:0000:0000:0000:0000",
                "2001:0DB8:1234:5678:ABCD:EF01:2345:6789",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
                "2001:0DB8:aaaa:0007:0000:0000:0000:0001",
                "2001:2::10",
                "2001:44b8:4126:f600:91bd:970c:9073:12df",
                "2001:4860:4860::8888",
                "2001:500:2d::d",
                "2001:558:fc03:11:5e63:3eff:fe67:edf9",
                "2001:acad:abad:1::bc",
                "2001:b50:ffd3:76:ce58:32ff:fe00:e7",
                "2001:db8::0:1:0:0:1",
                "2001:db8::1",
                "2001:db8::1:0:0:1",
                "2001:db8::212:7403:ace0:1",
                "2001:DB8::4:5:6:7",
                "2001:db8::5",
                "2001:DB8::8:800:200C:417A",
                "2001:db8::aaaa:0:0:1",
                "2001:db8:0::1",
                "2001:db8:0:0::1",
                "2001:db8:0:0:0::1",
                "2001:db8:0:0:1::1",
                "2001:DB8:0:0:1::1",
                "2001:db8:0:0:1:0:0:1",
                "2001:DB8:0:0:8:800:200C:417A",
                "2001:db8:0:0:aaaa::1",
                "2001:db8:0000:0:1::1",
                "2001:db8:3c4d:15::1",
                "2001:DB8:85A3::8A2E:370:7334",
                "2001:db8:aaaa:bbbb:cccc:dddd::1",
                "2001:db8:aaaa:bbbb:cccc:dddd:0:1",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:001",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:01",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA",
                "2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa",
                "2001:db8:d03:bd70:fede:5c4d:8969:12c4",
                "2002::8364:7777",
                "2002:4559:1FE2::4559:1FE2",
                "2002:C000:203:200::",
                "2002:cb0a:3cdd:1:1:1:1:1",
                "2400:8902::f03c:92ff:feb5:f66d",
                "2400:c980:0:e206:b07d:8cf9:2b05:fb06",
                "2400:cb00:2048:1::6814:507",
                "2404:6800:4009:805::2004",
                "2607:f8b0:4005:80b::200e",
                "2607:f8b0:400a:809::200e",
                "2620:0:1cfe:face:b00c::3",
                "2620:0:2d0:200::7",
                "3fff:ffff:3:1:0:0:0:7",
                "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
                "fc00::",
                "fd3b:d101:e37f:9713::1",
                "fd44:a77b:40ca:db17:37df:f4c4:f38a:fc81",
                //"FD92:7065:891e:8c71:d2e7:d3f3:f595:d7d8%tun0",
                "fe80::",
                "fe80::cd8:95bf:afbb:9622%eth0",
                "FE80:0000:0000:0000:0202:B3FF:FE1E:8329",
                "FE80:0000:0000:0000:0202:B3FF:FE1E:8329%eth0",
                "fe80:dead:beef:cafe:face:feed:f12d:bedd%2",
                "fec0:0:0:1::1",
                "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210",
                "FF01::101",
                "FF01:0:0:0:0:0:0:1",
                "FF01:0:0:0:0:0:0:101",
                "FF02::1",
                "FF02:0:0:0:0:0:0:1",
                "FF02:0:0:0:0:0:0:a",
                "FF05:15:25:df:20:4a:b4:24",
                "FF08:0:0:0:0:0:0:fc",
                "fe80:abc1::ffff:192.168.2.2",
                "fe80:ABC1::192.168.2.2"

            };

            string[] invalidIPv6Addresses =
            {
                "::-1",
                "::/0/0",
                "::%eth0",
                "::ffff:0.0.0.256",
                "::ffff:127.0.0.1/96",
                "::ffff:192.0.2.128/33",
                "::ffff:192.0.2.256",
                "::ffff:192.168.1.256",
                "### 1080:0:0:0:8:800:200C:417",
                "### 2001:cdba:0000:0000:0000:0000:3257:9652%4294967295",
                "1:2:3:4:5:6:7:8:9",
                "1080:0:0:0:0:0:0:192.88.99",
                "2001::0223:dead:beef::1",
                "2001::dead::beef",
                "2001::ff4:2:1:1:1:1:1",
                "2001:0DB8:0:CD3",
                "2001:0db8:1234:5678:90AB:CDEF:0012:3456:789a",
                "2001:db8:::1:0",
                "2001:db8::1 ::2",
                "2001:db8:/60",
                "2001:db8:0:0:0:0:0/64",
                "2001:db8:0:0:0:0:f:1g",
                "2001:db8:0:0:0g00:1428:57ab",
                "2001:db8:0:1:::1",
                "2001:db8:0:1::/129",
                "2001:db8:0:1::1::1",
                "2001:db8:0:1::a:b:c:d:e:f",
                "2001:db8:0:1:/64",
                "2001:db8:0:1:1:1:1::1",
                "2001:db8:0:1:1:1:1:1:1",
                "2001:db8:0:1g:0:0:0:1",
                "2001:db8:aaaa:bbbb:cccc:dddd-eeee:ffff",
                "2001:db8:aaaa:bbbb:cccc:dddd-eeee:ffff",
                "2001:dg8:0:0:0:0:1428:57ab",
                "2001:dg8:0:0:0:0:1428:57ab",
                "2001:gdba:0000:0000:0000:0000:3257:9652",
                "2001:gdba:0000:0000:0000:0000:3257:9652",
                "2001:ggg:0:0:0:0:1428:57ab",
                "2001:ggg:0:0:0:0:1428:57ab",
                "2001.x:0:0:0:0:0:0:1",
                "20011:db8:0:1:1:1:1:1",
                "2403:780:f:102:a:a:1:0:0",
                "2403:780:f:102:a:a:1:0:0",
                "2403:780:f:102:g:a:1:0",
                "2403:780:f:102:g:a:1:0",
                "260.02:00a:b:10:abc:def:123f:2552",
                "260.02:00a:b:10:abc:def:123f:2552",
                "fe80:::1",
                "fe80::7::8",
                "2001:0DB8:0:CD3",
            };
            foreach (string item in ipv6Addresses)
            {
                bool validate = ValidateIPv6Part2(item);
                if (validate)
                {
                    Console.WriteLine(string.Format("Valid - {0}", item));
                }
                else
                {
                    Console.WriteLine(string.Format("Not valid - {0}", item));
                }
            }
            Console.WriteLine("\n Valid Addresses \n");
            foreach (string item in validIPv6Addresses)
            {
                bool validate = ValidateIPv6Part2(item);
                if (validate)
                {
                    Console.WriteLine(string.Format("Valid - {0}", item));
                }
                else
                {
                    Console.WriteLine(string.Format("Not valid - {0}", item));
                }
            }
            Console.WriteLine("\n Invalid Addresses \n");
            foreach (string item in invalidIPv6Addresses)
            {
                bool validate = ValidateIPv6Part2(item);
                if (validate)
                {
                    Console.WriteLine(string.Format("Valid - {0}", item));
                }
                else
                {
                    Console.WriteLine(string.Format("Not valid - {0}", item));
                }
            }
        }

        static bool ValidateIPv6(string ipAddress)
        {
            if (ipAddress == null)
            {
                return false;
            }

            IPAddress ipaddress;
            bool isValid = IPAddress.TryParse(ipAddress, out ipaddress);

            return isValid && ipaddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        static bool ValidateIPv6Part2(string ipAddress)
        {
            if (ipAddress.Equals("::") || ipAddress.Equals("::1"))
            {
                return true;
            }

            if (ipAddress.Contains("::") && (ipAddress.IndexOf("::") != ipAddress.LastIndexOf("::")))
            {
                return false;
            }

            if (ipAddress.Contains("/") && (ipAddress.IndexOf("/") != ipAddress.LastIndexOf("/")))
            {
                return false;
            }

            string[] parts = ipAddress.Split(':');

            if (parts.Length < 3 || parts.Length > 8)
            {
                return false;
            }

            if (parts.Length < 8 && !((ipAddress.Contains("::")) || ipAddress.Contains(".")))
            {
                return false;
            }

            int partCounter = 0;

            foreach (string part in parts)
            {
                if (part.Equals(""))
                {
                    partCounter++;
                    continue;
                }

                if (part.Contains(".") && partCounter == parts.Length - 1)
                {
                    return ValidateIPv4(part);
                }

                if (part.Length > 4)
                {
                    bool valid = false;
                    foreach (char c in part)
                    {
                        if (!IsHexDigit(c))
                        {
                            if (ipAddress.Contains("fe80:") || ipAddress.Contains("FE80:"))
                            {
                                if (c == '%' && partCounter == parts.Length - 1)
                                {
                                    partCounter++;
                                    valid = true;
                                    break;
                                }
                            }
                            if (c == '/' && partCounter == parts.Length - 1)
                            {
                                string[] p = part.Split('/');
                                if (p.Length == 2)
                                {
                                    try
                                    {
                                        int num = Int32.Parse(p[1]);
                                        valid = true;
                                        break;
                                    }
                                    catch (Exception ex)
                                    {
                                        return false;
                                    }
                                }
                            }
                            return false;
                        }
                    }
                    if (!valid)
                    {
                        return false; // Each part should be a hexadecimal with a length of 1 to 4 characters
                    }
                }
                if (part.Length >= 1 && part.Length <= 4)
                {
                    foreach (char c in part)
                    {
                        if (!IsHexDigit(c))
                        {
                            return false;
                        }
                    }
                }
                partCounter++;
            }
            return true;
        }

        static bool IsHexDigit(char c)
        {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        }

        static bool ValidateIPv4(string ipAddress)
        {
            string[] parts = ipAddress.Split('.');

            if (ipAddress.Contains(" "))
            {
                return false;
            }
            try
            {
                if (ipAddress.StartsWith(".") || ipAddress.EndsWith(".") || parts.Length != 4)
                {
                    return false;
                }

                foreach (string p in parts)
                {
                    int numVal = Int32.Parse(p);
                    if (numVal < 0 || numVal > 255)
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
