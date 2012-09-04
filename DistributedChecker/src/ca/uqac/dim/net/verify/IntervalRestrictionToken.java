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

/**
 * Explanation token showing how the possible interval for packets
 * is being restricted by taking a routing rule.
 * @author sylvain
 *
 */
public class IntervalRestrictionToken extends ExplanationToken
{
  protected int m_left;
  protected int m_right;
  
  public IntervalRestrictionToken(int left, int right)
  {
    super();
    m_left = left;
    m_right = right;
  }
  
  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    sb.append("The considered interval becomes restricted to [").append(m_left).append("-").append(m_right).append("]");
    return sb.toString();
  }
}
