package org.jahia.service.render.filter;


import org.apache.commons.net.util.SubnetUtils;

import org.jahia.exceptions.JahiaForbiddenAccessException;
import org.jahia.services.content.JCRContentUtils;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.filter.AbstractFilter;
import org.jahia.services.render.filter.RenderChain;
import org.slf4j.Logger;

import javax.jcr.RepositoryException;
import java.util.Map;

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
        String address = renderContext.getRequest().getRemoteAddr();

        JCRNodeWrapper currentNode = renderContext.getMainResource().getNode();

        if ("127.0.0.1".equals(address)) {
            // on localhost we use the testIP value as fake address
            address = currentNode.hasProperty("testIp") ? currentNode.getProperty("testIp").getString().trim() : null;
        }
        if (address != null) {
            boolean hasIPRestriction = checkPathRestriction(currentNode, address);
            logger.debug("hasIPRestriction is " + hasIPRestriction);
            if (hasIPRestriction) {
                throw new JahiaForbiddenAccessException();
            }
        }

        return null;
    }

    private boolean checkPathRestriction(JCRNodeWrapper node, String address) {
        String path = node.getPath();
        try {
            if (node.isNodeType("jnt:page")) {
                String ipRangeList = node.hasProperty("ipRangeList") ? node.getProperty("ipRangeList").getString() : null;
                if (ipRangeList != null) {
                    String delimiter = ",";
                    String[] ranges = ipRangeList.split(delimiter);
                    for (int i = 0; i < ranges.length; i++) {
                        String range = ranges[i].trim();
                        SubnetUtils utils = new SubnetUtils(range);
                        if (utils.getInfo().isInRange(address)) {
                            logger.debug("Found IP restriction for page [" + path + "] : [" + address + "] is in subnet [" + range + "]");
                            return true;
                        }
                    }
                } else {
                    logger.debug("No IP restrictions for page [" + path + "]. Checking parent");
                    JCRNodeWrapper parentPage = JCRContentUtils.getParentOfType(node, "jnt:page");
                    if (parentPage != null) {
                        return checkPathRestriction(parentPage, address);
                    }
                }
            } else {
                logger.debug("Node [" + path + "] is not a page");
            }
        } catch (RepositoryException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        return false;
    }
}

