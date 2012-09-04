/*-------------------------------------------------------------------------
    Distributed Firewall Anomaly Detector
    Copyright (C) 2012  Sylvain Hallé

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -------------------------------------------------------------------------*/
package ca.uqac.dim.net.verify;

import java.io.IOException;
import java.util.Random;

import ca.uqac.net.rules.*;
import ca.uqac.logic.vl.Utilities;

public class NetworkGenerator
{
  public int m_maxAddress = 27;
  public int m_minFirewallRules = 1;
  public int m_maxFirewallRules = 50;
  public int m_degree = 3;
  
  protected Network m_network;
  
  private int m_nodeNum = 1; // We start at 1, 0 is reserved for "leaving the network"
  
  public Random m_rand;
  
  public static void main(String args[])
  {
    experiment2();
    System.exit(0);
  }
  
  /**
   * Networks with a fixed topology; random number of firewall
   * rules
   */
  public static void experiment1()
  {
    // Number of experiments to conduct
    int num_experiments = 100;
    
    // Generate all the different networks
    for (int experiment_counter = 0; experiment_counter < num_experiments; experiment_counter++)
    {
      long seed = System.currentTimeMillis();
      NetworkGenerator ng = new NetworkGenerator(seed);
      ng.buildNetwork();
      try
      {
        String file_prefix = "exp-" + experiment_counter + "-";
        ng.outputToDir("/tmp/ramdisk", file_prefix);
      }
      catch (IOException e)
      {
        System.err.println("Cannot output network to files");
        System.exit(1);
      }      
    }    
  }
  
  /**
   * Networks with a fixed number of firewall rules per node; increasing
   * number of nodes with random topology
   */
  public static void experiment2()
  {
    int total_rules = 100;
    int experiment_count = 100;
    for (int exp = 0; exp < experiment_count; exp++)
    {
      long seed = System.currentTimeMillis();
      NetworkGenerator ng = new NetworkGenerator(seed);
      int netsize = ng.m_rand.nextInt(20) + 2;
      ng.m_minFirewallRules = Math.round(total_rules / netsize);
      ng.m_maxFirewallRules = Math.round(total_rules / netsize);
      ng.m_maxAddress = netsize;
      ng.m_network = new Network();
      for (int i = 0; i < netsize; i++)
        ng.m_network.add(ng.buildRandomNode(i, 10, netsize));
      try
      {
        String file_prefix = "exp-" + exp + "-";
        ng.outputToDir("/tmp/ramdisk", file_prefix);
      }
      catch (IOException e)
      {
        System.err.println("Cannot output network to files");
        System.exit(1);
      }  
    }
  }
  
  public NetworkGenerator()
  {
    super();
    m_network = new Network();
    m_rand = new Random();
  }
  
  public NetworkGenerator(long seed)
  {
    this();
    m_rand.setSeed(seed);
  }
  
  public void outputToDir(String dir, String prefix) throws IOException
  {
    String slash = System.getProperty("file.separator");
    if (!dir.endsWith(slash))
      dir += slash;
    for (int a : m_network.m_nodes.keySet())
    {
      String filename = dir + prefix + "node-" + a + ".txt";
      NetworkNode n = m_network.m_nodes.get(a);
      Utilities.writeStringAsFile(filename, n.toString());
    }
  }
  
  private void buildNetwork()
  {
    buildNode(-1, 1, m_maxAddress, 0, 3);
  }
  
  public int buildNode(int parent, int address_l, int address_r, int level, int max_level)
  {
    if (level == max_level)
      return 0;
    NetworkNode nn = new NetworkNode();
    // Build routing table
    int range = address_r - address_l + 1;
    int slice = range / m_degree;
    int m_nodeName = m_nodeNum;
    nn.m_address = m_nodeName;
    m_nodeNum++;
    RoutingTable rt = new RoutingTable();
    for (int i = 0; i < m_degree; i++)
    {
      int left = address_l + i * slice;
      int right = left + slice - 1;
      if (i == m_degree - 1)
        right = address_r; // To avoid gaps created by rounding to nearest integer
      int child_no = buildNode(m_nodeName, left, right, level + 1, max_level);
      RoutingRule rr = new RoutingRule(left, right, child_no);
      rt.add(rr);
    }
    nn.m_routingT = rt;
    
    // Build random firewall
    nn.m_firewall = buildFirewall();
    
    // Add node to network
    m_network.add(nn);
    
    return m_nodeName;
  }
  
  /**
   * Generates a random routing table
   * @param node_num
   * @param max_routing_rules
   * @param max_nodes
   */
  protected NetworkNode buildRandomNode(int node_num, int max_routing_rules, int max_nodes)
  {
    int num_rules = m_rand.nextInt(max_routing_rules) + 2;
    NetworkNode nn = new NetworkNode();
    nn.m_address = node_num;
    m_nodeNum++;
    RoutingTable rt = new RoutingTable();
    for (int i = 0; i < num_rules; i++)
    {
      int left = m_rand.nextInt(max_nodes - 1);
      int right = m_rand.nextInt(max_nodes - left) + left;
      int dest = m_rand.nextInt(max_nodes);
      RoutingRule rr = new RoutingRule(left, right, dest);
      rt.add(rr);
    }
    nn.m_routingT = rt;
    nn.m_firewall = buildFirewall();
    return nn;
  }
  
  protected FirewallRuleList buildFirewall()
  {
    FirewallRuleList frl = new FirewallRuleList();
    double log_min = Math.log10(m_minFirewallRules);
    double log_max = Math.log10(m_maxFirewallRules);
    //int num_rules = m_rand.nextInt(m_maxFirewallRules - m_minFirewallRules) + m_minFirewallRules;
    double log_num_rules = m_rand.nextFloat() * (log_max - log_min) + log_min;
    int num_rules = (int) Math.pow(10, log_num_rules);
    for (int i = 0; i < num_rules; i++)
    {
      String decision = "accept";
      if (m_rand.nextBoolean())
        decision = "reject";
      int left = m_rand.nextInt(m_maxAddress - 1);
      int right = m_rand.nextInt(m_maxAddress - left) + left;
      StringBuilder sb = new StringBuilder();
      sb.append("0: 0,0,0,").append(left).append(",").append(right).append(",dummy,").append(decision);
      FirewallRule r = new FirewallRule(sb.toString());
      frl.add(r);
    }
    return frl;
  }
}
