package org.jahia.service.render.filter;


import org.apache.commons.net.util.SubnetUtils;

import org.jahia.exceptions.JahiaForbiddenAccessException;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.filter.AbstractFilter;
import org.jahia.services.render.filter.RenderChain;
import org.slf4j.Logger;


/**
 * Created by IntelliJ IDEA.
 * User: pol
 * Date: 29.05.12
 * Time: 14:10
 * To change this template use File | Settings | File Templates.
 */
public class IPFilter extends AbstractFilter {
    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(IPFilter.class);


    public String prepare(RenderContext renderContext, Resource resource, RenderChain chain) throws Exception {
        String currentAddress = renderContext.getRequest().getRemoteAddr();
        JCRNodeWrapper siteNode = (JCRNodeWrapper) renderContext.getSite();
        String filterType = siteNode.hasProperty("filterType") ? siteNode.getProperty("filterType").getString() : null;
        if (filterType != null) {
            if ("127.0.0.1".equals(currentAddress)) {
                // on localhost we use the testIP value as fake currentAddress
                currentAddress = siteNode.hasProperty("testIp") ? siteNode.getProperty("testIp").getString().trim() : null;
            }
            if (currentAddress != null) {
                String ipRangeList = siteNode.hasProperty("ipRangeList") ? siteNode.getProperty("ipRangeList").getString() : null;
                if (ipRangeList != null) {
                    boolean inRange = isInRange(currentAddress, ipRangeList);
                    if ("deny".equals(filterType)) {
                        if (inRange) {
                            logger.warn("IPFilter - Deny rule: IP [" + currentAddress + "] is in subnet [" + ipRangeList + "]");
                            throw new JahiaForbiddenAccessException();
                        }
                    } else { // onlyallow
                        if (!inRange) {
                            logger.warn("IPFilter - Only Allow rule:  IP [" + currentAddress + "] not in subnet [" + ipRangeList + "]");
                            throw new JahiaForbiddenAccessException();
                        }
                    }
                }
            } else {
                logger.debug("IPFilter - Bypass IP filtering for localhost");
            }
        }
        return null;
    }

    private boolean isInRange(String address, String ipRangeList) {
        if (ipRangeList != null) {
            String delimiter = ",";
            String[] ranges = ipRangeList.split(delimiter);
            for (int i = 0; i < ranges.length; i++) {
                String range = ranges[i].trim();
                SubnetUtils utils = new SubnetUtils(range);
                if (utils.getInfo().isInRange(address)) {
                    return true;
                }
            }
        }
        return false;
    }
}

