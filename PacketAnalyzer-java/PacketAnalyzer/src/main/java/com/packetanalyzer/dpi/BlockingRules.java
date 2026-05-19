package com.packetanalyzer.dpi;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.FiveTuple;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Holds and evaluates packet blocking rules.
 * Supports blocking by source IP, application type, or domain substring.
 */
public class BlockingRules {

    private final Set<Long>     blockedIps     = new HashSet<>();
    private final Set<AppType>  blockedApps    = new HashSet<>();
    private final List<String>  blockedDomains = new ArrayList<>();

    public void blockIp(String ip) {
        long addr = FiveTuple.parseIp(ip);
        blockedIps.add(addr);
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void blockApp(String appName) {
        for (AppType app : AppType.values()) {
            if (app.toString().equalsIgnoreCase(appName)) {
                blockedApps.add(app);
                System.out.println("[Rules] Blocked app: " + appName);
                return;
            }
        }
        System.err.println("[Rules] Unknown app: " + appName);
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    /**
     * Returns true if the packet should be dropped.
     *
     * @param srcIp   source IP (unsigned 32-bit stored in long)
     * @param appType detected application type
     * @param sni     detected SNI / Host header (may be empty)
     */
    public boolean isBlocked(long srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedApps.contains(appType)) return true;
        String lowerSni = sni.toLowerCase();
        for (String dom : blockedDomains) {
            if (lowerSni.contains(dom)) return true;
        }
        return false;
    }
}
