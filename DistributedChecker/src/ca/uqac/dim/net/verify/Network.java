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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ca.uqac.net.rules.*;

/**
 * Abstract representation of a network of distributed firewalls.
 * A network is made of a number of {@link NetworkNodes}, each
 * having its own ingress firewall and routing table. This class is
 * responsible for:
 * <ol>
 * <li>Constructing a Kripke structure from each node's firewalls and
 *   routing tables, in the form of a NuSMV input model that can then
 *   be used to detect anomalies through model checking (see {@link toSmv})</li>
 * <li>Process the counter-example trace returned by NuSMV (if any)
 *   and build an {@link ExplanationTrace} describing the presence
 *   of an anomaly (see {@link explain})</li>
 * </ol>
 * @author sylvain
 *
 */
public class Network
{
  /**
   * The list of all nodes in the network
   */
  protected Map<Integer,NetworkNode> m_nodes;

  /**
   * The list of all states in the resulting model
   */
  protected Map<Integer,Integer> m_minima;
  protected Map<Integer,Integer> m_maxima;

  /**
   * The next available state number
   */
  private int m_currentState;
  
  /**
   * The upper bound to the pool of addresses
   */
  protected int m_maxAddress;

  public Network()
  {
    super();
    m_nodes = new HashMap<Integer,NetworkNode>();
    m_minima = new HashMap<Integer,Integer>();
    m_maxima = new HashMap<Integer,Integer>();
    m_currentState = 1;
    m_maxAddress = -1;
  }
  
  /**
   * Computes the number of nodes in the network
   * @return The number of nodes
   */
  public int getNodeSize()
  {
    return m_nodes.size();
  }
  
  /**
   * Computes the total number of firewall rules in the network 
   * @return The number of rules
   */
  public int getFirewallRuleSize()
  {
    int out = 0;
    for (int a : m_nodes.keySet())
    {
      NetworkNode n = m_nodes.get(a);
      out += n.m_firewall.size();
    }
    return out;
  }
  
  /**
   * Computes the total number of rules in all routing tables in the network 
   * @return The number of rules
   */
  public int getRoutingTableSize()
  {
    int out = 0;
    for (int a : m_nodes.keySet())
    {
      NetworkNode n = m_nodes.get(a);
      out += n.m_routingT.size();
    }
    return out;
  }

  /**
   * Add a node to the network
   * @param n
   */
  public void add(NetworkNode n)
  {
    // Add the node
    int a = n.getAddress();
    m_nodes.put(a, n);
    // Assign unique state numbers to every firewall rule of every network node
    m_minima.put(a, m_currentState);
    m_currentState += n.m_firewall.size();
    m_maxima.put(a, m_currentState - 1);
    // Update address range
    RoutingTable t = n.m_routingT;
    for (RoutingRule r : t)
    {
      if (r.fieldEnd("Destination") > m_maxAddress)
        m_maxAddress = r.fieldEnd("Destination");
    }
  }
  
  /**
   * Creates a NuSMV model from the network 
   * @return A String that can be used as a NuSMV input model
   */
  public String toSmv()
  {
    return toSmv(false);
  }
  
  /**
   * Sets the maximum range for addresses in the model
   * @param max The maximuma address (minimum is 1)
   */
  public void setAddressRange(int max)
  {
    m_maxAddress = max;
  }

  /**
   * Creates a NuSMV model from the network
   * @param show_comments Set to true to display comments through the file
   *   for improved readability 
   * @return A String that can be used as a NuSMV input model
   */
  public String toSmv(boolean show_comments)
  {
    // The last number is a dummy state number
    int n_sink_state = 0;
    StringBuilder sb = new StringBuilder();

    // Declaration of variables
    sb.append("MODULE main\n\nVAR\n");
    sb.append(" interval_l : 0..").append(m_maxAddress).append(";\n");
    sb.append(" interval_r : 0..").append(m_maxAddress).append(";\n");
    sb.append(" decision : {accept, reject};\n");
    sb.append(" rule_interval_l : 0..").append(m_maxAddress).append(";\n");
    sb.append(" rule_interval_r : 0..").append(m_maxAddress).append(";\n");
    sb.append(" rule_decision : {accept, reject};\n");
    sb.append(" frozen : boolean;\n");
    sb.append(" cur_rule : 0..").append(m_currentState - 1).append(";\n\n");

    // Initial values for variables
    sb.append("INIT\n");
    sb.append("interval_l = 0 & ");
    sb.append("interval_r = ").append(m_maxAddress).append(" & ");
    sb.append("decision = accept & ");
    sb.append("frozen = FALSE & ");
    sb.append("(\n");
    for (Integer a : m_nodes.keySet())
    {
      NetworkNode n = m_nodes.get(a);
      FirewallRule first_rule = n.m_firewall.firstElement();
      int min = m_minima.get(a);
      String dec = "reject";
      if (first_rule.getDecision())
        dec = "accept";
      sb.append(" (cur_rule = ").append(min).append(" & rule_interval_l = ").append(first_rule.fieldBeg("Destination")).append(" & rule_interval_r = ").append(first_rule.fieldEnd("Destination")).append(" & rule_decision = ").append(dec).append(")\n");
      sb.append(" |");
    }
    sb.append(" FALSE)");
    sb.append("\n\n");

    // Transition relation
    sb.append("TRANS\n");

    // Transitions corresponding to firewall rule interval
    if (show_comments)
    {
      sb.append("--\n");
      sb.append("-- Interval and decision for each firewall rule\n");
      sb.append("--\n");      
    }
    for (Integer a : m_nodes.keySet())
    {
      NetworkNode n = m_nodes.get(a);
      int rule_num = m_minima.get(a);
      if (show_comments)
        sb.append("-- Firewall for device ").append(a).append("\n");
      for (FirewallRule r : n.m_firewall)
      {
        sb.append("(next(cur_rule) = ").append(rule_num).append(" -> (\n");
        sb.append("  next(rule_interval_l) = ").append(r.fieldBeg("Destination")).append(" &\n");
        sb.append("  next(rule_interval_r) = ").append(r.fieldEnd("Destination")).append(" &\n");;
        String dec = "reject";
        if (r.getDecision())
          dec = "accept";
        sb.append("  next(rule_decision) = ").append(dec).append("))\n&\n");;
        rule_num++;
      }
    }

    // If we are not at the last rule of a firewall, we simply go down to the next rule
    if (show_comments)
    {
      sb.append("--\n");
      sb.append("-- For all firewall rules except the last in each device, increment the rule counter\n");
      sb.append("-- and possibly freeze the current interval\n");
      sb.append("--\n");
    }
    sb.append("((");
    for (Integer a : m_nodes.keySet())
    {
      sb.append(" (cur_rule >= ").append(m_minima.get(a)).append(" & cur_rule < ").append(m_maxima.get(a)).append(") |\n");
    }
    sb.append(" FALSE) -> (\n");
    sb.append(" (next(interval_l) > next(interval_r) & next(cur_rule) = ").append(n_sink_state).append(") |\n");
    sb.append(" (next(interval_l) <= next(interval_r) & next(cur_rule) = cur_rule + 1 & (\n");
    sb.append("  (next(frozen) = frozen\n    & next(interval_l) = interval_l\n    & next(interval_r) = interval_r\n    & next(decision) = decision) |\n");
    sb.append("  (!frozen\n    & next(frozen) = TRUE\n    & next(interval_l) = rule_interval_l\n    & next(interval_r) = rule_interval_r\n    & next(decision) = rule_decision))\n");
    sb.append(")))\n&\n");

    // If we are at the last rule of the firewall, we pick one rule in the routing table
    // and move to the first firewall rule of the target node
    if (show_comments)
    {
      sb.append("--\n");
      sb.append("-- For the last firewall rules of each device, pick one rule in the routing table,\n");
      sb.append("-- move to the first firewall rule of the target node, and possibly freeze the\n");
      sb.append("-- intersection of the current firewall rule interval with\n");
      sb.append("--\n");
    }
    for (Integer a : m_nodes.keySet())
    {
      NetworkNode n = m_nodes.get(a);
      RoutingTable rt = n.m_routingT;
      FirewallRuleList ft = n.m_firewall;
      FirewallRule last_fw_rule = ft.lastElement();
      StringBuilder rb = new StringBuilder();
      sb.append("(cur_rule = ").append(m_maxima.get(a)).append(" -> (\n");
      for (RoutingRule r : rt)
      {
        int destination = r.getDecision();
        int beg = r.fieldBeg("Destination");
        int end = r.fieldEnd("Destination");
        rb.append(" |\n");
        rb.append(" (((interval_l >= ").append(beg).append(" | interval_r >= ").append(beg).append(") & (interval_l <= ").append(end).append(" | interval_r <= ").append(end).append(")) &"); 
        if (!m_nodes.keySet().contains(destination))
        {
          // The target is an unknown destination: we interpret this as
          // the packet leaving the network
          rb.append(" next(cur_rule) = ").append(n_sink_state).append("\n");
        }
        else
        {
          rb.append(" (next(cur_rule) = ").append(m_minima.get(destination)).append(" &\n");
          if (show_comments)
            rb.append("   -- If an interval is frozen, we trim it to the bounds of the routing rule's interval\n");
          rb.append("   (frozen -> (\n");
          rb.append("     ((interval_l < ").append(beg).append(" & next(interval_l) = ").append(beg).append(") | (interval_l >= ").append(beg).append(" & next(interval_l) = interval_l)) &\n");
          rb.append("     ((interval_r > ").append(end).append(" & next(interval_r) = ").append(end).append(") | (interval_r <= ").append(end).append(" & next(interval_r) = interval_r)) &\n");
          rb.append("     next(decision) = decision &\n");
          rb.append("     next(frozen) = frozen)\n");
          rb.append("   ) &\n");
          if (show_comments)
            rb.append("   -- If an interval is not frozen...\n");
          rb.append("   (!frozen -> (\n");
          rb.append("     (");
          if (show_comments)
            rb.append(" -- Either it remains unfrozen and its bounds are trimmed to that of the routing rule\n");
          rb.append("      next(frozen) = FALSE &\n");
          rb.append("      ((interval_l < ").append(beg).append(" & next(interval_l) = ").append(beg).append(") | (interval_l >= ").append(beg).append(" & next(interval_l) = interval_l)) &\n");
          rb.append("      ((interval_r > ").append(end).append(" & next(interval_r) = ").append(end).append(") | (interval_r <= ").append(end).append(" & next(interval_r) = interval_r)) &\n");
          rb.append("      next(decision) = decision) |\n");
          rb.append("     (");
          if (show_comments)
            rb.append(" -- Or we freeze it\n");
          rb.append("      next(frozen) = TRUE &\n");
          rb.append("      next(interval_l) = ").append(Math.max(beg, last_fw_rule.fieldBeg("Destination"))).append(" &\n");
          rb.append("      next(interval_r) = ").append(Math.min(end, last_fw_rule.fieldEnd("Destination"))).append(" &\n");
          rb.append("      next(decision) = rule_decision)\n");
          rb.append("   ))\n");
          rb.append(" )\n");
        }
        rb.append(")\n");
      }
      if (rb.toString().startsWith(" |"))
        sb.append(rb.substring(2)); // Trim leading " | "
      sb.append("))\n&\n");
    }

    // Once in sink state, stay in sink state
    if (show_comments)
    {
      sb.append("--\n");
      sb.append("-- Once in a sink state, stay in sink state\n");
      sb.append("--\n");
    }
    sb.append("((cur_rule = ").append(n_sink_state).append(" | next(cur_rule) = ").append(n_sink_state).append(") -> (\n");
    sb.append("  next(cur_rule) = ").append(n_sink_state).append("\n");
    sb.append("  & next(rule_interval_l) = 0 & next(rule_interval_r) = 0 & next(rule_decision) = accept\n");
    sb.append("  & next(frozen) = FALSE & next(interval_l) = 0 & next(interval_r) = 0 & next(decision) = accept");
    sb.append("))\n&\n");
    // Trim last "&"
    return sb.substring(0, sb.length() - 2);
  }
  
  /**
   * Produce an explanation trace from NuSMV's answer
   * @param nusmv_answer The answer produced by NuSMV from processing the
   * model produced by {@link toSmv}
   * @return An {@link ExplanationTrace} describing how an anomaly is present in the network
   */
  public ExplanationTrace explain(String nusmv_answer) throws NuSmvParseException
  {
    ExplanationTrace out_trace = new ExplanationTrace();
    Pattern patt;
    Matcher m;
    StringBuffer sb = new StringBuffer();
    
    // Remove useless first lines
    patt = Pattern.compile("^.*\\*\\*\\*.*$", Pattern.MULTILINE);
    m = patt.matcher(nusmv_answer);
    while (m.find())
      m.appendReplacement(sb, "");
    m.appendTail(sb);
    nusmv_answer = sb.toString().trim();
    
    // Check whether the property is violated or not
    patt = Pattern.compile("-- specification .* is (.*)$", Pattern.MULTILINE);
    m = patt.matcher(nusmv_answer);
    if (!m.find())
      throw new NuSmvParseException(); // Problem: can't parse NuSMV answer
    String value = m.group(1).trim();
    if (value.compareTo("true") == 0)
      return null; // Spec is true: over
    // Spec is false: split the trace according to each state
    String[] states = nusmv_answer.split("-> State: .*? <-");
    Map<String,String> values = new HashMap<String,String>();
    boolean first_group = true, previous_frozen = false;
    int current_device = -1, previous_rule = -1, prev_interval_l = -1, prev_interval_r = -1;
    for (String lines : states)
    {
      if (first_group)
      {
        // We ignore the first group, which contains text before the first
        // state of the counterexample trace
        first_group = false;
        continue;
      }
      
      // Extract parameter values of the state
      patt = Pattern.compile("^\\s*([^\\s]+?) = (.*)$", Pattern.MULTILINE);
      m = patt.matcher(lines);
      while (m.find())
      {
        String var_name = m.group(1);
        String var_value = m.group(2);
        values.put(var_name, var_value);
      }
      int cur_rule = new Integer(values.get("cur_rule")).intValue();
      // If we are at sink state, don't care and move to the next state
      if (cur_rule == 0)
        continue;
      int rule_interval_l = new Integer(values.get("rule_interval_l")).intValue();
      int rule_interval_r = new Integer(values.get("rule_interval_r")).intValue();
      int interval_l = new Integer(values.get("interval_l")).intValue();
      int interval_r = new Integer(values.get("interval_r")).intValue();
      boolean current_frozen = false;
      if (values.get("frozen").compareToIgnoreCase("true") == 0)
        current_frozen = true;
      int device_no = getDeviceFromRule(cur_rule).getAddress();
      int prev_rule_index = previous_rule - m_minima.get(device_no) + 1;
      int cur_rule_index = cur_rule - m_minima.get(device_no) + 1;
      boolean decision = false;
      if (values.get("decision").compareToIgnoreCase("accept") == 0)
        decision = true;
      boolean rule_decision = false;
      if (values.get("rule_decision").compareToIgnoreCase("accept") == 0)
        rule_decision = true;
      
      // Have we frozen an interval?     
      if (previous_frozen != current_frozen)
      {
        FirewallRuleToken fr = new FirewallRuleToken(prev_rule_index, interval_l, interval_r, decision, device_no);
        out_trace.add(fr);
      }
      
      // Have we changed device?
      if (current_device != -1 && current_device != device_no)
      {
        // Yes, we create a new routing event
        RoutingRule rr = getRoutingRuleFromSpecs(current_device, interval_l, interval_r, device_no);
        RoutingTableToken te = new RoutingTableToken(rr.fieldBeg("Destination"), rr.fieldEnd("Destination"), device_no, current_device);
        out_trace.add(te);
      }
      else if (current_device == -1)
      {
        // No, but we are at the initial state
        out_trace.add(new StartToken(device_no));
      }
      
      // Has the interval changed?
      if (previous_rule != -1 && previous_frozen == current_frozen && (prev_interval_l != interval_l || prev_interval_r != interval_r))
      {
        out_trace.add(new IntervalRestrictionToken(interval_l, interval_r));
      }
      
      // Is there an anomaly?
      if (current_frozen)
      {
        if (interval_l <= rule_interval_l && interval_r >= rule_interval_r && decision != rule_decision)
        {
          // Shadowing anomaly
          out_trace.add(new ShadowingAnomalyToken(device_no, rule_interval_l, rule_interval_r, rule_decision, cur_rule_index));
        }
      }
      
      // Set device number to current device
      current_device = device_no;
      previous_rule = cur_rule;
      prev_interval_l = interval_l;
      prev_interval_r = interval_r;
      previous_frozen = current_frozen;
    }
    return out_trace;
  }
  
  /**
   * Retrieve the routing rule responsible for the transition to a new hop
   * @param device_no
   * @param beg
   * @param end
   * @param destination
   * @return
   */
  protected RoutingRule getRoutingRuleFromSpecs(int device_no, int beg, int end, int destination)
  {
    NetworkNode n = m_nodes.get(device_no);
    for (RoutingRule r : n.m_routingT)
    {
      if (r.getDecision() != destination)
        continue;
      int left = r.fieldBeg("Destination");
      int right = r.fieldEnd("Destination");
      if ((beg >= left || end >= left) && (beg <= right || end <= right))
        return r;
    }
    return null;
  }
  
  /**
   * Retrieve the device associated to a rule of given number
   * @param rule_no The rule number in the NuSMV model
   * @return The address (i.e. name) of the device that contains this rule
   */
  protected NetworkNode getDeviceFromRule(int rule_no)
  {
    for (int a : m_nodes.keySet())
    {
      int min = m_minima.get(a);
      int max = m_maxima.get(a);
      if (rule_no >= min && rule_no <= max)
        return m_nodes.get(a);
    }
    return null;
  }
  
  @Override
  public String toString()
  {
    StringBuilder out = new StringBuilder();
    for (int a : m_nodes.keySet())
    {
      NetworkNode n = m_nodes.get(a);
      out.append(n).append("\n");
    }
    return out.toString();
  }
}
