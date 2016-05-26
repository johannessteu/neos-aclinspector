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
use TYPO3\Neos\Security\Authorization\Privilege\NodeTreePrivilege;
use TYPO3\TYPO3CR\Domain\Model\NodeInterface;
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
     * @param ACLCheckerDto $dto
     * @return array
     */
    public function resolveDto(ACLCheckerDto $dto)
    {
        $checkedNodes = [];

        $nodes = $this->getNodes($dto);
        $roles = $this->getRolesByDto($dto);

        foreach ($nodes as $node) {
            if ($node instanceof NodeInterface) {
                $checkedNodes[] = $this->checkNodeForRoles($node, $roles);
            }
        }

        return $checkedNodes;
    }

    /**
     * @param NodeInterface $node
     * @return array
     */
    public function checkNodeForRoles(NodeInterface $node, array $roles)
    {
        $checkedNodes = [
            'node' => [
                'nodeData' => $node,
                'title' => $node->getProperty('title')
            ],
            'acl' => []
        ];

        foreach ($roles as $role) {
            /** @var Role $role */
            $checkedNodes['acl'][$role->getIdentifier()] = [
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
        if (empty($dto->getStartOnNodePath())) {
            return [];
        }

        $context = $this->contextFactory->create(array('workspaceName' => 'live'));

        if($dto->getStopOnNodePath() !== '') {
            try {
                $nodes = $context->getNodesOnPath($dto->getStartOnNodePath(), $dto->getStopOnNodePath());
            } catch (\InvalidArgumentException $e) {
                $nodes = [];
            }
        } else {
            $nodes = [$context->getNode($dto->getStartOnNodePath())];
        }

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

}