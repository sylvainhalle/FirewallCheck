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
 * Explanation token describing the occurrence of an anomaly.
 * @author sylvain
 *
 */
public class AnomalyToken extends ExplanationToken
{
  protected int m_left;
  protected int m_right;
  protected boolean m_decision;
  protected int m_ruleno;
  
  /**
   * Constructor. Simply populates the token with its relevant information.
   * @param device
   * @param left
   * @param right
   * @param decision
   * @param number
   */
  public AnomalyToken(int device, int left, int right, boolean decision, int number)
  {
    super();
    m_deviceName = device;
    m_left = left;
    m_right = right;
    m_decision = decision;
    m_ruleno = number;
  }
}
