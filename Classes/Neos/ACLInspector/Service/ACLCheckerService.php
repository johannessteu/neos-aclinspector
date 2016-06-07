<?php
namespace Neos\ACLInspector\Service;

/*
 * This file is part of the Neos.ACLInspector package.
 */
use Neos\ACLInspector\Dto\ACLCheckerDto;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Authorization\PrivilegeManagerInterface;
use TYPO3\Flow\Security\Exception\NoSuchRoleException;
use TYPO3\Flow\Security\Policy\PolicyService;
use TYPO3\Flow\Security\Policy\Role;
use TYPO3\Neos\Domain\Repository\SiteRepository;
use TYPO3\Neos\Security\Authorization\Privilege\NodeTreePrivilege;
use TYPO3\TYPO3CR\Domain\Model\NodeInterface;
use TYPO3\TYPO3CR\Domain\Model\NodeLabelGeneratorInterface;
use TYPO3\TYPO3CR\Domain\Service\ContextFactoryInterface;
use TYPO3\TYPO3CR\Security\Authorization\Privilege\Node\CreateNodePrivilege;
use TYPO3\TYPO3CR\Security\Authorization\Privilege\Node\CreateNodePrivilegeSubject;
use TYPO3\TYPO3CR\Security\Authorization\Privilege\Node\EditNodePrivilege;
use TYPO3\TYPO3CR\Security\Authorization\Privilege\Node\NodePrivilegeSubject;
use TYPO3\TYPO3CR\Security\Authorization\Privilege\Node\RemoveNodePrivilege;

class ACLCheckerService
{
    /**
     * @Flow\Inject
     * @var ContextFactoryInterface
     */
    protected $contextFactory;

    /**
     * @Flow\Inject
     * @var PrivilegeManagerInterface
     */
    protected $privilegeManager;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var SiteRepository
     */
    protected $siteRepository;

    /**
     * @Flow\Inject
     * @var  NodeLabelGeneratorInterface
     */
    protected $nodeLabelGenerator;

    /**
     * @param ACLCheckerDto $dto
     * @return array
     */
    public function resolveDto(ACLCheckerDto $dto)
    {
        return $this->getNodes($dto);
    }

    /**
     * @param NodeInterface $node
     * @return array
     */
    public function checkNodeForRoles(NodeInterface $node, array $roles)
    {
        $checkedNodes = [];

        foreach ($roles as $role) {
            /** @var Role $role */
            $checkedNodes[$role->getIdentifier()] = [
                'editNode' => $this->privilegeManager->isGrantedForRoles([$role], EditNodePrivilege::class, new NodePrivilegeSubject($node), $debug),
                'removeNode' => $this->privilegeManager->isGrantedForRoles([$role], RemoveNodePrivilege::class, new NodePrivilegeSubject($node)),
                'createNodeOfType' => $this->privilegeManager->isGrantedForRoles([$role], CreateNodePrivilege::class, new CreateNodePrivilegeSubject($node)),
                'showInTree' => $this->privilegeManager->isGrantedForRoles([$role], NodeTreePrivilege::class, new NodePrivilegeSubject($node))
            ];
        }
        return $checkedNodes;
    }

    /**
     * @param ACLCheckerDto $dto
     * @return array
     */
    protected function getNodes(ACLCheckerDto $dto)
    {
        $context = $this->contextFactory->create(array('workspaceName' => 'live'));

        $site = $this->siteRepository->findFirstOnline();
        $startNode = $context->getNode('/sites/' . $site->getNodeName());

        $roles = $this->getRolesByDto($dto);

        $nodes = [];
        $this->getChildNodeData($nodes, $startNode, $roles, $dto->getNodeTreeLoadingDepth());

        return $nodes;
    }

    /**
     * @param ACLCheckerDto $dto
     * @return array
     */
    protected function getRolesByDto(ACLCheckerDto $dto)
    {
        $roles = [];
        foreach ($dto->getRoles() as $roleIdentifier) {
            try {
                $roles[] = $this->policyService->getRole($roleIdentifier);
            } catch (NoSuchRoleException $e) {
            }
        }
        return $roles;
    }

    /**
     * @param array $nodes
     * @param NodeInterface $node
     * @param array $roles
     * @param int $depth
     * @param int $recursionPointer
     * @param string $nodeTypeFilter
     */
    protected function getChildNodeData(array &$nodes, $node, $roles, $depth = 0, $recursionPointer = 1, $nodeTypeFilter = 'TYPO3.Neos:Document')
    {
        foreach ($node->getChildNodes($nodeTypeFilter) as $childNode) {
            /** @var NodeInterface $childNode */
            $expand = ($depth === 0 || $recursionPointer < $depth);

            $properties = [
                'nodeIdentifier' => $childNode->getIdentifier(),
                'nodePath' => $childNode->getPath(),
                'nodeLabel' => $childNode->getLabel(),
                'nodeType' => $childNode->getNodeType()->getName(),
                'nodeLevel' => $childNode->getDepth(),
                'acl' => $this->checkNodeForRoles($childNode, $roles)
            ];

            if($expand && $childNode->hasChildNodes($nodeTypeFilter)) {
                $properties['childNodes'] = [];
                $this->getChildNodeData($properties['childNodes'], $childNode, $roles, $depth, ($recursionPointer + 1), $nodeTypeFilter);
            }

            array_push($nodes, $properties);
        }
    }
}